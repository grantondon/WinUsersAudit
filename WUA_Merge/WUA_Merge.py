#!/usr/bin/env python3
"""Merge WinUsersAudit 1.0.1 ZIP reports into one XLSX workbook."""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter


MAX_EXCEL_ROWS = 1_048_576
OUTPUT_NAME = "WUA_Merge.xlsx"
DANGEROUS_PREFIXES = ("=", "+", "-", "@")

CSV_SPECS = {
    "int": [
        "hostname", "Имя подключения", "Описание", "Индекс интерфейса",
        "MAC-адрес", "Состояние подключения", "TCP/IP включён", "IP-адрес",
        "Маска подсети", "Основной шлюз", "DNS-серверы, в порядке использования",
        "DHCP включён", "DHCP-сервер", "Получение аренды", "Окончание аренды",
    ],
    "netstat": [
        "hostname", "Протокол", "Локальный IP-адрес", "Локальный порт",
        "Удалённый IP-адрес", "Удалённый порт", "Состояние", "PID",
        "Имя процесса", "Путь к исполняемому файлу", "Владелец процесса",
    ],
    "route": [
        "hostname", "Сеть назначения", "Маска", "Следующий узел",
        "Имя подключения", "Индекс интерфейса", "Метрика",
    ],
    "software": [
        "hostname", "Название ПО", "Версия", "Издатель", "Дата установки",
        "Путь установки", "Размер, КБ", "Область установки", "Пользователь",
        "Разрядность", "Системный компонент", "Тип выпуска",
    ],
    "user": [
        "hostname", "Версия ОС", "Пользователь", "Полное имя", "Описание",
        "Локальная УЗ?", "SID", "Членство в локальных группах",
        "Пароль требуется?", "Возраст пароля", "Пароль можно изменить?",
        "Срок действия пароля истекает?", "Пароль просрочен?", "УЗ отключена?",
        "УЗ заблокирована?", "Последний вход", "Окончание действия УЗ",
        "Число неудачных входов", "Максимальный срок действия пароля",
        "Минимальная длина пароля", "Минимальный срок действия пароля",
        "Требования сложности пароля", "Требования неповторяемости паролей",
        "Порог блокировки после ошибочных входов", "Время блокировки",
        "Время сброса счётчика ошибочных входов",
    ],
}

DIAG_COLUMNS = [
    "hostname", "Версия ОС", "Принадлежность к домену или рабочей группе",
    "Роль компьютера", "Многоногость", "Интернет (ping)", "Интернет (http)",
    "Производитель", "Модель", "Оперативная память", "NTP",
    "Автоматическая защита сеанса",
]
UNKNOWN = "Не определено"


class CsvValidationError(Exception):
    """The member is not a compatible WinUsersAudit CSV."""


@dataclass
class Message:
    level: str
    archive: str
    member: str
    text: str


class SheetWriter:
    def __init__(self, workbook: Workbook, report_type: str) -> None:
        self.workbook = workbook
        self.report_type = report_type
        self.header = ["Папка", *(DIAG_COLUMNS if report_type == "diag" else CSV_SPECS[report_type])]
        self.sheets = []
        self.current = None
        self.current_rows = 0
        self.total_rows = 0
        self._new_sheet()

    def _new_sheet(self) -> None:
        index = len(self.sheets) + 1
        title = self.report_type if index == 1 else f"{self.report_type}_{index}"
        sheet = self.workbook.create_sheet(title)
        sheet.freeze_panes = "A2"
        sheet.column_dimensions["A"].width = 32
        for column in range(2, len(self.header) + 1):
            sheet.column_dimensions[get_column_letter(column)].width = 24
        sheet.append([self._header_cell(sheet, value) for value in self.header])
        self.current = sheet
        self.current_rows = 1
        self.sheets.append(sheet)

    @staticmethod
    def _header_cell(sheet, value: str) -> WriteOnlyCell:
        cell = WriteOnlyCell(sheet, value=value)
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="D9EAF7")
        return cell

    def append(self, folder: str, row: list[str]) -> None:
        if self.current_rows >= MAX_EXCEL_ROWS:
            self._new_sheet()
        self.current.append([safe_excel_text(folder), *map(safe_excel_text, row)])
        self.current_rows += 1
        self.total_rows += 1

    def finalize(self) -> None:
        for sheet in self.sheets:
            rows = self.current_rows if sheet is self.current else MAX_EXCEL_ROWS
            sheet.auto_filter.ref = f"A1:{get_column_letter(len(self.header))}{rows}"


def safe_excel_text(value: str) -> str:
    """Prevent formula interpretation while preserving the displayed text."""
    if value and value.startswith(DANGEROUS_PREFIXES):
        return "'" + value
    return value


def csv_type_for_member(member_name: str) -> str | None:
    basename = Path(member_name).name.lower()
    for report_type in CSV_SPECS:
        if basename.endswith(f"_{report_type}.csv"):
            return report_type
    return None


def csv_rows(zip_file: zipfile.ZipFile, member: zipfile.ZipInfo) -> Iterator[list[str]]:
    try:
        with zip_file.open(member, "r") as raw:
            if raw.read(2) != b"\xff\xfe":
                raise CsvValidationError("ожидалась кодировка UTF-16 LE с BOM")
            with io.TextIOWrapper(raw, encoding="utf-16-le", errors="strict", newline="") as text:
                reader = csv.reader(text, delimiter=";", quotechar='"', strict=True)
                for row in reader:
                    yield row
    except (UnicodeError, csv.Error, OSError, zipfile.BadZipFile) as exc:
        raise CsvValidationError(str(exc)) from exc


def validate_csv(zip_file: zipfile.ZipFile, member: zipfile.ZipInfo, report_type: str) -> int:
    expected_header = CSV_SPECS[report_type]
    rows = csv_rows(zip_file, member)
    try:
        header = next(rows)
    except StopIteration as exc:
        raise CsvValidationError("CSV пустой: отсутствует строка заголовков") from exc

    if header != expected_header:
        raise CsvValidationError(
            "несовместимый заголовок: ожидались точные названия и порядок "
            f"{len(expected_header)} колонок, получено {len(header)}"
        )

    data_rows = 0
    for line_number, row in enumerate(rows, start=2):
        if not row or all(value == "" for value in row):
            continue
        if len(row) != len(expected_header):
            raise CsvValidationError(
                f"строка {line_number}: ожидалось {len(expected_header)} колонок, "
                f"получено {len(row)}"
            )
        data_rows += 1
    return data_rows


def append_csv(
    zip_file: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    report_type: str,
    folder: str,
    writer: SheetWriter,
    computers: set[str],
) -> None:
    rows = csv_rows(zip_file, member)
    next(rows)  # Header was already checked by validate_csv.
    for row in rows:
        if not row or all(value == "" for value in row):
            continue
        writer.append(folder, row)
        if row[0]:
            computers.add(row[0])


def relative_folder(base_dir: Path, archive: Path) -> str:
    relative = archive.parent.relative_to(base_dir)
    return "" if relative == Path(".") else relative.as_posix()


def add_message(messages: list[Message], level: str, archive: Path, member: str, text: str) -> None:
    messages.append(Message(level, archive.as_posix(), member, text))


def multihomed(rows: list[list[str]]) -> str:
    networks = set()
    uncertain = False
    inactive = {"отключено", "оборудование отсутствует", "оборудование отключено",
                "неисправность оборудования", "сетевой кабель не подключён"}
    for row in rows:
        status = row[5].strip().casefold()
        if status not in ("подключено", "подключен", "подключён"):
            if status not in inactive:
                uncertain = True
            continue
        addresses = [v.strip() for v in row[7].split(",") if v.strip()]
        masks = [v.strip() for v in row[8].split(",") if v.strip()]
        if not addresses and not masks and row[6].strip().casefold() == "нет":
            continue
        if not addresses or len(addresses) != len(masks):
            uncertain = True
            continue
        for address, mask in zip(addresses, masks):
            try:
                ip = ipaddress.ip_address(address.split("%", 1)[0])
                if ip.version == 6:
                    continue
                if ip.is_unspecified:
                    uncertain = True
                    continue
                networks.add(ipaddress.IPv4Network((address, mask), strict=False))
            except ValueError:
                uncertain = True
    if len(networks) >= 2:
        return "Да"
    return UNKNOWN if uncertain else "Нет"


def log_value(lines: list[str], key: str) -> str:
    values = [line[len(key):].strip() for line in lines if line.startswith(key)]
    return values[0] if len(values) == 1 and values[0] else UNKNOWN


def log_section(lines: list[str], start: str, end: str) -> list[str]:
    try:
        first = lines.index(start)
        last = lines.index(end, first + 1)
        return lines[first + 1:last]
    except ValueError:
        return []


def internet_result(lines: list[str], protocol: str) -> str:
    prefix = "PING " if protocol == "ping" else "HTTP "
    entries = [line for line in lines if line.startswith(prefix)]
    if protocol == "ping":
        if any(line.endswith(": успешно") for line in entries):
            return "Есть"
        failures = [line for line in entries if re.search(r": нет ответа, код -?\d+$", line)]
    else:
        if any(re.search(r": ответ получен, статус \d+$", line) for line in entries):
            return "Есть"
        failures = [line for line in entries if ": ошибка, код " in line or ": недопустимый статус " in line]
    targets = {line.split(": ", 1)[0] for line in failures}
    return "Нет" if len(entries) == 5 and len(targets) == 5 and len(failures) == 5 else UNKNOWN


def ntp_result(lines: list[str]) -> str:
    service = log_value(lines, "Служба Windows Time (W32Time): ")
    if re.search(r"(?:^|;\s*)запуск=Disabled(?:;|$)", service, re.I):
        return "Служба отключена"
    mode = log_value(lines, "Режим синхронизации (Type): ").split(";", 1)[0].strip().upper()
    if mode == "NOSYNC":
        return "Синхронизация отсутствует"
    source = log_value(lines, "Текущий источник времени: ")
    if source.casefold() in ("local cmos clock", "локальные часы cmos"):
        return "Синхронизация отсутствует"
    # A reported source alone does not prove a successful exchange.
    if source != UNKNOWN and any(re.search(r"(?:Last Successful Sync Time|Время последней успешной синхронизации):\s*\d", line, re.I) for line in lines):
        return "Синхронизация работает"
    return UNKNOWN


def session_result(lines: list[str], interactive_user: str) -> str:
    if not lines or interactive_user == UNKNOWN:
        return UNKNOWN
    profiles = []
    current = None
    for line in lines:
        if line.startswith("Пользователь: "):
            current = [line[len("Пользователь: "):].strip()]
            profiles.append(current)
        elif current is not None:
            current.append(line.strip())
    matching = [p for p in profiles if p[0].casefold() == interactive_user.casefold()]
    if len(matching) != 1:
        return UNKNOWN
    profile = matching[0]
    secure = log_value(profile[1:], "Защищенная заставка: ")
    match = re.match(r"срабатывает через (\d+) секунд", secure)
    if match and int(match.group(1)) > 0:
        seconds = int(match.group(1))
        minutes, remaining = divmod(seconds, 60)
        duration = (f"{minutes} мин" if minutes else "") + (f" {remaining} сек" if remaining else "")
        return f"Включена ({duration.strip()}, пароль)"
    machine = log_value(lines, "Системный тайм-аут бездействия: ")
    active = log_value(profile[1:], "Заставка включена: ").split(";", 1)[0].strip()
    password = log_value(profile[1:], "Запрос учетных данных: ").split(";", 1)[0].strip()
    if (machine in ("не настроен", "отключен (0)") or machine.startswith("не поддерживается")) and (active == "Нет" or password == "Нет"):
        return "Не настроена"
    return UNKNOWN


def build_diag(zip_file, log_member, selected, valid, folder, archive, messages):
    try:
        with zip_file.open(log_member) as stream:
            if stream.read(2) != b"\xff\xfe":
                raise ValueError("ожидалась кодировка UTF-16 LE с BOM")
            lines = io.TextIOWrapper(stream, encoding="utf-16-le", errors="strict").read().splitlines()
    except (ValueError, UnicodeError, OSError, zipfile.BadZipFile) as exc:
        add_message(messages, "Ошибка", archive, log_member.filename, f"Лог недоступен: {exc}")
        lines = []
    host = log_value(lines, "Компьютер: ")
    version = UNKNOWN
    interfaces = None
    for kind in ("user", "int"):
        # Associate CSV with this log, not merely with the enclosing archive.
        expected = log_member.filename[:-len("_diag.log")] + f"_{kind}.csv"
        matches = [item for item in zip_file.infolist() if not item.is_dir() and item.filename.casefold() == expected.casefold()]
        if len(matches) != 1:
            add_message(messages, "Предупреждение", archive, expected, "Соответствующий CSV отсутствует или неоднозначен")
            continue
        member = matches[0]
        try:
            if selected.get(kind) is not member or kind not in valid:
                validate_csv(zip_file, member, kind)
        except CsvValidationError as exc:
            add_message(messages, "Ошибка", archive, member.filename, f"CSV для diag недоступен: {exc}")
            continue
        rows = list(csv_rows(zip_file, member))[1:]
        rows = [row for row in rows if row and any(row)]
        row_hosts = {row[0].strip().casefold() for row in rows if row[0].strip()}
        if host != UNKNOWN and row_hosts and row_hosts != {host.casefold()}:
            add_message(messages, "Предупреждение", archive, member.filename, "hostname CSV не совпадает с диагностическим логом")
            continue
        if host == UNKNOWN and len(row_hosts) == 1:
            host = next(row[0].strip() for row in rows if row[0].strip())
        if kind == "int":
            if rows or log_value(lines, "Обнаружено сетевых интерфейсов: ") == "0":
                interfaces = rows
        else:
            versions = {row[1].strip() for row in rows if row[1].strip() and row[1].strip() != UNKNOWN}
            if len(versions) == 1:
                version = versions.pop()
    membership = log_value(lines, "Принадлежность к домену или рабочей группе: ")
    if membership.startswith("домен ") and membership[6:].strip():
        membership = "Домен: " + membership[6:].strip()
    elif membership.startswith("рабочая группа ") and membership[15:].strip():
        membership = "Рабочая группа: " + membership[15:].strip()
    else:
        membership = UNKNOWN
    role = log_value(lines, "Роль компьютера: ")
    role = next((value for prefix, value in (("рабочая станция", "Рабочая станция"), ("рядовой сервер", "Сервер"), ("контроллер домена", "Контроллер домена")) if role.startswith(prefix)), UNKNOWN)
    memory = log_value(lines, "Оперативная память: ")
    memory_match = re.match(r"^(\d+) байт", memory)
    memory = (f"{int(memory_match.group(1)) / 1073741824:.2f}".rstrip("0").rstrip(".") + " ГБ") if memory_match else UNKNOWN
    internet = log_section(lines, "--- Проверка доступности Интернета ---", "--- Конец проверки доступности Интернета ---")
    ntp = log_section(lines, "--- Синхронизация времени Windows ---", "--- Конец синхронизации времени Windows ---")
    session = log_section(lines, "--- Автоматическая защита сеанса ---", "--- Конец проверки автоматической защиты сеанса ---")
    return [host, version, membership, role, multihomed(interfaces) if interfaces is not None else UNKNOWN,
            internet_result(internet, "ping"), internet_result(internet, "http"),
            log_value(lines, "Производитель: "), log_value(lines, "Модель: "), memory,
            ntp_result(ntp), session_result(session, log_value(lines, "Текущий интерактивный пользователь: "))]


def process_archive(
    archive: Path,
    base_dir: Path,
    writers: dict[str, SheetWriter],
    computers: set[str],
    messages: list[Message],
) -> tuple[bool, bool]:
    """Return (opened_and_scanned, has_errors)."""
    has_errors = False
    folder = relative_folder(base_dir, archive)
    try:
        with zipfile.ZipFile(archive, "r") as zip_file:
            bad_member = zip_file.testzip()
            if bad_member is not None:
                add_message(messages, "Ошибка", archive, bad_member, "ZIP повреждён (ошибка CRC)")
                return False, True

            selected: dict[str, zipfile.ZipInfo] = {}
            for member in zip_file.infolist():
                if member.is_dir():
                    continue
                report_type = csv_type_for_member(member.filename)
                if report_type is None:
                    continue
                if report_type in selected:
                    has_errors = True
                    add_message(
                        messages, "Предупреждение", archive, member.filename,
                        f"повторный CSV типа {report_type} пропущен",
                    )
                    continue
                selected[report_type] = member

            valid = set()
            for report_type in CSV_SPECS:
                member = selected.get(report_type)
                if member is None:
                    add_message(messages, "Предупреждение", archive, "", f"CSV типа {report_type} отсутствует")
                    continue
                try:
                    row_count = validate_csv(zip_file, member, report_type)
                    valid.add(report_type)
                    append_csv(zip_file, member, report_type, folder, writers[report_type], computers)
                    add_message(messages, "Успешно", archive, member.filename, f"объединено строк: {row_count}")
                except CsvValidationError as exc:
                    has_errors = True
                    add_message(messages, "Ошибка", archive, member.filename, f"CSV пропущен: {exc}")
                except Exception as exc:  # Do not let one member stop the audit set.
                    has_errors = True
                    add_message(messages, "Ошибка", archive, member.filename, f"CSV пропущен: {type(exc).__name__}: {exc}")
            logs = [member for member in zip_file.infolist() if not member.is_dir() and member.filename.lower().endswith("_diag.log")]
            if not logs:
                add_message(messages, "Предупреждение", archive, "", "Диагностический лог отсутствует")
            for log_member in logs:
                try:
                    before = len(messages)
                    writers["diag"].append(folder, build_diag(zip_file, log_member, selected, valid, folder, archive, messages))
                    if any(message.level == "Ошибка" for message in messages[before:]):
                        has_errors = True
                except Exception as exc:
                    has_errors = True
                    add_message(messages, "Ошибка", archive, log_member.filename, f"Ошибка разбора диагностики: {type(exc).__name__}: {exc}")
                    writers["diag"].append(folder, [UNKNOWN] * len(DIAG_COLUMNS))
            return True, has_errors
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        add_message(messages, "Ошибка", archive, "", f"ZIP не обработан: {type(exc).__name__}: {exc}")
        return False, True
    except Exception as exc:
        add_message(messages, "Ошибка", archive, "", f"ZIP не обработан: {type(exc).__name__}: {exc}")
        return False, True


def write_summary(
    workbook: Workbook,
    archives: list[Path],
    processed_archives: int,
    archives_with_errors: int,
    writers: dict[str, SheetWriter],
    computers: set[str],
    folder_stats: Counter[str],
    messages: list[Message],
) -> None:
    sheet = workbook.create_sheet("summary")
    sheet.freeze_panes = "A2"
    sheet.column_dimensions["A"].width = 30
    sheet.column_dimensions["B"].width = 55
    sheet.column_dimensions["C"].width = 45
    sheet.column_dimensions["D"].width = 90

    sheet.append(["Сводка WUA_Merge"])
    sheet.append(["Дата и время формирования", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    sheet.append(["Найдено ZIP", len(archives)])
    sheet.append(["Успешно обработано ZIP", processed_archives])
    sheet.append(["Архивов с ошибками", archives_with_errors])
    sheet.append(["Уникальных компьютеров", len(computers)])
    sheet.append([])
    sheet.append(["Тип CSV", "Собрано строк", "Создано листов"])
    for report_type in (*CSV_SPECS, "diag"):
        writer = writers[report_type]
        sheet.append([report_type, writer.total_rows, len(writer.sheets)])

    sheet.append([])
    sheet.append(["Каталог", "Найдено ZIP"])
    for folder, count in sorted(folder_stats.items()):
        sheet.append([folder, count])

    sheet.append([])
    sheet.append(["Статус", "ZIP", "CSV", "Сообщение"])
    for message in messages:
        sheet.append([message.level, message.archive, message.member, message.text])


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    archives = sorted(path for path in base_dir.rglob("*") if path.is_file() and path.suffix.lower() == ".zip")
    output_path = base_dir / OUTPUT_NAME
    temporary_output = base_dir / f".{OUTPUT_NAME}.tmp"

    workbook = Workbook(write_only=True)
    writers = {report_type: SheetWriter(workbook, report_type) for report_type in CSV_SPECS}
    writers["diag"] = SheetWriter(workbook, "diag")
    computers: set[str] = set()
    messages: list[Message] = []
    folder_stats: Counter[str] = Counter(relative_folder(base_dir, archive) for archive in archives)
    processed_archives = 0
    archives_with_errors = 0

    for archive in archives:
        processed, has_errors = process_archive(archive, base_dir, writers, computers, messages)
        if processed and not has_errors:
            processed_archives += 1
        if has_errors:
            archives_with_errors += 1

    for writer in writers.values():
        writer.finalize()
    write_summary(
        workbook, archives, processed_archives, archives_with_errors, writers,
        computers, folder_stats, messages,
    )
    try:
        workbook.save(temporary_output)
        os.replace(temporary_output, output_path)
    except Exception as exc:
        print(f"Ошибка создания {output_path}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"Найдено ZIP: {len(archives)}")
    print(f"Успешно обработано ZIP: {processed_archives}")
    print(f"Архивов с ошибками: {archives_with_errors}")
    print(f"Excel-файл: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
