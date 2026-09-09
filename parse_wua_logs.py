#!/usr/bin/env python3
"""Parse WUA1 logs into consolidated UTF-16 CSV reports."""

from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


FORMAT_SIGNATURE = "WUA1"
SERVICE_COLUMNS = [
    "Идентификатор запуска",
    "Имя исходного файла",
    "Статус запуска",
    "Версия формата",
    "Версия схемы",
    "Время начала запуска",
    "Время окончания запуска",
    "Лог завершён",
]
EVENT_COLUMNS = [
    "Идентификатор запуска",
    "Время события",
    "Уровень",
    "Подсистема",
    "Сообщение",
    "Код ошибки",
    "Описание ошибки",
]
OUTPUTS = OrderedDict(
    [
        ("USER", "users.csv"),
        ("PASSWORD_POLICY", "password_policies.csv"),
        ("INTERFACE", "interfaces.csv"),
        ("ROUTE", "routes.csv"),
        ("FIREWALL_PROFILE", "firewall.csv"),
        ("CONNECTION", "netstat.csv"),
        ("PING", "ping.csv"),
        ("HTTP", "http.csv"),
        ("EVENT", "diagnostics.csv"),
    ]
)
KNOWN_DATA_TYPES = set(OUTPUTS) | {"SYSTEM"}
RUN_COUNT_TYPES = ["SYSTEM"] + list(OUTPUTS)


@dataclass
class ParseIssue:
    file_name: str
    line_number: int
    run_id: str
    record_type: str
    level: str
    description: str
    raw: str


@dataclass
class DataRecord:
    data_type: str
    schema_version: str
    schema_columns: List[str]
    values: List[str]
    ordinal: int


@dataclass
class Run:
    path: Path
    file_name: str
    format_version: str = ""
    run_id: str = ""
    hostname: str = ""
    start_time: str = ""
    script_version: str = ""
    os_caption: str = ""
    os_version: str = ""
    end_time: str = ""
    end_status: str = ""
    has_end: bool = False
    structure_ok: bool = True
    schemas: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    records: List[DataRecord] = field(default_factory=list)
    counts: Counter = field(default_factory=Counter)
    issues: List[ParseIssue] = field(default_factory=list)
    selected: bool = False
    selection_reason: str = ""

    @property
    def complete(self) -> bool:
        return self.has_end and self.end_status in {"COMPLETE", "COMPLETE_WITH_WARNINGS"}

    @property
    def status(self) -> str:
        if self.has_end:
            return self.end_status or "Не определено"
        return "UNFINISHED"


def safe_raw(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def unescape_value(value: str) -> str:
    result: List[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\" or index + 1 >= len(value):
            result.append(char)
            index += 1
            continue
        escaped = value[index + 1]
        if escaped == "\\":
            result.append("\\")
        elif escaped == "r":
            result.append("\r")
        elif escaped == "n":
            result.append("\n")
        elif escaped == "t":
            result.append("\t")
        else:
            result.extend(("\\", escaped))
        index += 2
    return "".join(result)


def add_issue(
    run: Run,
    line_number: int,
    record_type: str,
    level: str,
    description: str,
    raw: str,
) -> None:
    run.issues.append(
        ParseIssue(
            run.file_name,
            line_number,
            run.run_id,
            record_type,
            level,
            description,
            safe_raw(raw),
        )
    )
    if level == "ERROR":
        run.structure_ok = False


def parse_line(raw: str) -> List[str]:
    return next(csv.reader([raw], delimiter=";", quotechar='"', strict=True))


def parse_log(path: Path) -> Run:
    run = Run(path=path.resolve(), file_name=path.name)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        add_issue(run, 0, "FILE", "ERROR", f"Не удалось прочитать файл: {exc}", "")
        return run
    if not payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        add_issue(run, 1, "FILE", "ERROR", "Отсутствует BOM UTF-16", "")
        return run
    try:
        text = payload.decode("utf-16")
    except UnicodeDecodeError as exc:
        add_issue(run, 0, "FILE", "ERROR", f"Ошибка декодирования UTF-16: {exc}", "")
        text = payload.decode("utf-16", errors="replace")

    seen_file = False
    ordinal = 0
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw:
            add_issue(run, line_number, "", "WARNING", "Пустая физическая строка", raw)
            continue
        try:
            row = parse_line(raw)
        except csv.Error as exc:
            add_issue(run, line_number, "", "ERROR", f"Повреждённая CSV-строка: {exc}", raw)
            continue
        if not row or row[0] != FORMAT_SIGNATURE:
            add_issue(run, line_number, row[1] if len(row) > 1 else "", "ERROR", "Неверная сигнатура WUA1? expected WUA1", raw)
            continue
        if len(row) < 2:
            add_issue(run, line_number, "", "ERROR", "Не указан вид записи", raw)
            continue
        kind = row[1]
        if not seen_file and kind != "FILE":
            add_issue(run, line_number, kind, "ERROR", "Первая запись должна иметь вид FILE", raw)
        if kind == "FILE":
            if seen_file:
                add_issue(run, line_number, kind, "ERROR", "Повторная строка FILE", raw)
                continue
            if len(row) < 10:
                add_issue(run, line_number, kind, "ERROR", "Недостаточно полей в FILE", raw)
                continue
            seen_file = True
            run.format_version = row[2]
            run.run_id = unescape_value(row[3])
            run.hostname = unescape_value(row[4])
            run.start_time = unescape_value(row[5])
            run.script_version = unescape_value(row[6])
            run.os_caption = unescape_value(row[7])
            run.os_version = unescape_value(row[8])
            if run.format_version != "1":
                add_issue(run, line_number, kind, "WARNING", f"Неизвестная версия формата: {run.format_version}", raw)
        elif kind == "SCHEMA":
            if len(row) < 5:
                add_issue(run, line_number, kind, "ERROR", "Некорректная строка SCHEMA", raw)
                continue
            data_type, version = row[2], row[3]
            key = (data_type, version)
            columns = [unescape_value(value) for value in row[4:]]
            if key in run.schemas and run.schemas[key] != columns:
                add_issue(run, line_number, kind, "ERROR", "Противоречивое повторное описание SCHEMA", raw)
            else:
                run.schemas[key] = columns
        elif kind == "DATA":
            if len(row) < 4:
                add_issue(run, line_number, kind, "ERROR", "Некорректная строка DATA", raw)
                continue
            data_type, version = row[2], row[3]
            schema = run.schemas.get((data_type, version))
            if schema is None:
                add_issue(run, line_number, data_type, "ERROR", f"SCHEMA версии {version} не найдена", raw)
                continue
            values = [unescape_value(value) for value in row[4:]]
            if len(values) != len(schema):
                add_issue(
                    run,
                    line_number,
                    data_type,
                    "ERROR",
                    f"Число полей DATA ({len(values)}) не совпадает со SCHEMA ({len(schema)})",
                    raw,
                )
                continue
            if "Идентификатор запуска" in schema:
                run_value = values[schema.index("Идентификатор запуска")]
                if run.run_id and run_value != run.run_id:
                    add_issue(run, line_number, data_type, "ERROR", "Идентификатор запуска DATA не совпадает с FILE", raw)
            ordinal += 1
            run.records.append(DataRecord(data_type, version, schema, values, ordinal))
            run.counts[data_type] += 1
            if data_type not in KNOWN_DATA_TYPES:
                add_issue(run, line_number, data_type, "WARNING", "Неизвестный тип DATA пропущен при экспорте", raw)
        elif kind == "EVENT":
            if len(row) != 10:
                add_issue(run, line_number, kind, "ERROR", "Строка EVENT должна содержать 10 полей", raw)
                continue
            values = [unescape_value(value) for value in row[3:]]
            if run.run_id and values[0] != run.run_id:
                add_issue(run, line_number, kind, "ERROR", "Идентификатор запуска EVENT не совпадает с FILE", raw)
            ordinal += 1
            run.records.append(DataRecord("EVENT", row[2], EVENT_COLUMNS, values, ordinal))
            run.counts["EVENT"] += 1
            if len(values) > 2:
                run.counts[values[2]] += 1
        elif kind == "END":
            if len(row) < 5:
                add_issue(run, line_number, kind, "ERROR", "Некорректная строка END", raw)
                continue
            if run.has_end:
                add_issue(run, line_number, kind, "ERROR", "Повторная строка END", raw)
                continue
            run.has_end = True
            if run.run_id and unescape_value(row[2]) != run.run_id:
                add_issue(run, line_number, kind, "ERROR", "Идентификатор запуска END не совпадает с FILE", raw)
            run.end_status = unescape_value(row[3])
            run.end_time = unescape_value(row[4])
        else:
            add_issue(run, line_number, kind, "WARNING", "Неизвестный вид записи пропущен", raw)
    if not seen_file:
        add_issue(run, 0, "FILE", "ERROR", "Строка FILE не найдена", "")
    if not run.has_end:
        add_issue(run, 0, "END", "WARNING", "Строка END не найдена", "")
    return run


def timestamp_key(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.min


def select_runs(runs: List[Run], mode: str, include_partial: bool) -> None:
    eligible = [
        run
        for run in runs
        if run.complete or include_partial
    ]
    if mode == "all":
        for run in runs:
            run.selected = run in eligible
            run.selection_reason = "Выбран режимом --all" if run.selected else "Незавершённый запуск; требуется --include-partial"
        return
    by_host: Dict[str, List[Run]] = {}
    for run in eligible:
        by_host.setdefault(run.hostname or "Не определено", []).append(run)
    selected_ids = set()
    for host_runs in by_host.values():
        preferred = [run for run in host_runs if run.complete]
        candidates = preferred or host_runs
        selected = max(candidates, key=lambda item: (timestamp_key(item.end_time or item.start_time), timestamp_key(item.start_time)))
        selected_ids.add(id(selected))
    for run in runs:
        run.selected = id(run) in selected_ids
        if run.selected:
            run.selection_reason = "Последний завершённый запуск hostname" if run.complete else "Последний доступный незавершённый запуск"
        elif run not in eligible:
            run.selection_reason = "Незавершённый запуск; требуется --include-partial"
        else:
            run.selection_reason = "Пропущен: выбран более поздний запуск hostname"


def union_columns(runs: Iterable[Run], data_type: str) -> List[str]:
    result = list(SERVICE_COLUMNS)
    seen = set(result)
    for run in runs:
        for record in run.records:
            if record.data_type != data_type:
                continue
            for column in record.schema_columns:
                if column not in seen:
                    seen.add(column)
                    result.append(column)
    return result


def service_values(run: Run, schema_version: str) -> Dict[str, str]:
    return {
        "Идентификатор запуска": run.run_id or "Не определено",
        "Имя исходного файла": run.file_name,
        "Статус запуска": run.status,
        "Версия формата": run.format_version or "Не определено",
        "Версия схемы": schema_version or "Не определено",
        "Время начала запуска": run.start_time or "Не определено",
        "Время окончания запуска": run.end_time or "Не определено",
        "Лог завершён": "Да" if run.has_end else "Нет",
    }


def open_output(path: Path):
    return path.open("w", encoding="utf-16", newline="")


def write_data_outputs(output_dir: Path, runs: List[Run]) -> None:
    selected = [run for run in runs if run.selected]
    for data_type, file_name in OUTPUTS.items():
        columns = union_columns(selected, data_type)
        with open_output(output_dir / file_name) as stream:
            writer = csv.writer(stream, delimiter=";", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\r\n")
            writer.writerow(columns)
            for run in selected:
                for record in run.records:
                    if record.data_type != data_type:
                        continue
                    values = service_values(run, record.schema_version)
                    values.update(dict(zip(record.schema_columns, record.values)))
                    writer.writerow([values.get(column, "Не определено") for column in columns])


def write_runs(output_dir: Path, runs: List[Run]) -> None:
    count_types = RUN_COUNT_TYPES
    columns = [
        "Идентификатор запуска",
        "hostname",
        "Имя исходного файла",
        "Полный путь к исходному файлу",
        "Версия формата",
        "Версия WinUsersAudit",
        "Версия ОС",
        "Время начала",
        "Время окончания",
        "Наличие END",
        "Статус из END",
        "Файл полный или незавершённый",
    ] + [f"Количество {name}" for name in count_types] + [
        "Количество предупреждений",
        "Количество ошибок",
        "Результат проверки структуры",
        "Причина выбора или пропуска",
    ]
    with open_output(output_dir / "runs.csv") as stream:
        writer = csv.writer(stream, delimiter=";", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(columns)
        for run in runs:
            writer.writerow(
                [
                    run.run_id or "Не определено",
                    run.hostname or "Не определено",
                    run.file_name,
                    str(run.path),
                    run.format_version or "Не определено",
                    run.script_version or "Не определено",
                    " / ".join(filter(None, (run.os_caption, run.os_version))) or "Не определено",
                    run.start_time or "Не определено",
                    run.end_time or "Не определено",
                    "Да" if run.has_end else "Нет",
                    run.end_status or "Не определено",
                    "Полный" if run.complete else "Незавершённый",
                ]
                + [str(run.counts[name]) for name in count_types]
                + [
                    str(run.counts["WARNING"]),
                    str(run.counts["ERROR"]),
                    "Корректно" if run.structure_ok else "Есть ошибки",
                    run.selection_reason,
                ]
            )


def write_errors(output_dir: Path, runs: List[Run]) -> None:
    columns = [
        "Имя файла",
        "Номер физической строки",
        "Идентификатор запуска",
        "Тип записи",
        "Уровень ошибки",
        "Описание",
        "Исходное содержимое строки в безопасном виде",
    ]
    with open_output(output_dir / "parser_errors.csv") as stream:
        writer = csv.writer(stream, delimiter=";", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(columns)
        for run in runs:
            for issue in run.issues:
                writer.writerow(
                    [
                        issue.file_name,
                        str(issue.line_number),
                        issue.run_id or "Не определено",
                        issue.record_type,
                        issue.level,
                        issue.description,
                        issue.raw,
                    ]
                )


def find_logs(root: Path, include_partial: bool) -> List[Path]:
    seen = set()
    found = []
    patterns = ["*.wua.log"] + (["*.wua.partial"] if include_partial else [])
    for pattern in patterns:
        for path in root.rglob(pattern):
            resolved = path.resolve()
            try:
                stat = resolved.stat()
                key = (stat.st_dev, stat.st_ino)
            except OSError:
                key = os.path.normcase(str(resolved))
            if key not in seen and path.is_file():
                seen.add(key)
                found.append(path)
    return sorted(found, key=lambda item: os.path.normcase(str(item)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Разбор структурированных логов WinUsersAudit WUA1")
    parser.add_argument("input_dir", type=Path, help="Папка с логами")
    parser.add_argument("output_dir", type=Path, help="Папка результатов")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--all", action="store_true", help="Выгрузить все подходящие запуски (по умолчанию)")
    modes.add_argument("--latest", action="store_true", help="Выбрать последний завершённый запуск каждого hostname")
    parser.add_argument("--include-partial", action="store_true", help="Обрабатывать .wua.partial и незавершённые запуски")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input_dir.is_dir():
        print(f"Ошибка: папка с логами не найдена: {args.input_dir}", file=sys.stderr)
        return 2
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Ошибка создания папки результатов: {exc}", file=sys.stderr)
        return 2
    paths = find_logs(args.input_dir, args.include_partial)
    runs = [parse_log(path) for path in paths]
    select_runs(runs, "latest" if args.latest else "all", args.include_partial)
    write_data_outputs(args.output_dir, runs)
    write_runs(args.output_dir, runs)
    write_errors(args.output_dir, runs)
    print(f"Найдено файлов: {len(paths)}; выбрано запусков: {sum(run.selected for run in runs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
