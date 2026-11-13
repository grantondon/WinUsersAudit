#!/usr/bin/env python3
"""Merge WinUsersAudit 1.0.1 ZIP reports into one XLSX workbook."""

from __future__ import annotations

import csv
import io
import os
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
        self.header = ["Папка", *CSV_SPECS[report_type]]
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

            for report_type in CSV_SPECS:
                member = selected.get(report_type)
                if member is None:
                    add_message(messages, "Предупреждение", archive, "", f"CSV типа {report_type} отсутствует")
                    continue
                try:
                    row_count = validate_csv(zip_file, member, report_type)
                    append_csv(zip_file, member, report_type, folder, writers[report_type], computers)
                    add_message(messages, "Успешно", archive, member.filename, f"объединено строк: {row_count}")
                except CsvValidationError as exc:
                    has_errors = True
                    add_message(messages, "Ошибка", archive, member.filename, f"CSV пропущен: {exc}")
                except Exception as exc:  # Do not let one member stop the audit set.
                    has_errors = True
                    add_message(messages, "Ошибка", archive, member.filename, f"CSV пропущен: {type(exc).__name__}: {exc}")
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
    for report_type in CSV_SPECS:
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
