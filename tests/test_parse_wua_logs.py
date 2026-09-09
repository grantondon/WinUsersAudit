import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "parse_wua_logs.py"


def escaped(value):
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def make_log(
    path,
    run_id,
    hostname="PC-01",
    start="2026-09-09T10:00:00+03:00",
    end=True,
    status="COMPLETE",
    schema_version="1",
    columns=None,
    values=None,
    extra_rows=None,
):
    columns = columns or ["Идентификатор запуска", "Имя", "Описание", "Пусто"]
    values = values or [run_id, "Антон", 'Текст; с "кавычками"', ""]
    rows = [
        ["WUA1", "FILE", "1", run_id, hostname, start, "WinUsersAudit 4.0", "Windows", "10.0", "cscript.exe 5.812"],
        ["WUA1", "SCHEMA", "USER", schema_version] + columns,
        ["WUA1", "DATA", "USER", schema_version] + [escaped(value) for value in values],
        ["WUA1", "EVENT", "1", run_id, start, "INFO", "USER", escaped("CR\rLF\nTAB\t"), "", ""],
    ]
    rows.extend(extra_rows or [])
    if end:
        rows.append(["WUA1", "END", run_id, status, start, "USER=1", "INFO=1", "WARNING=0", "ERROR=0"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-16", newline="") as stream:
        writer = csv.writer(stream, delimiter=";", quotechar='"', quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerows(rows)


def read_csv(path):
    with path.open("r", encoding="utf-16", newline="") as stream:
        return list(csv.reader(stream, delimiter=";", quotechar='"'))


class ParserTests(unittest.TestCase):
    def run_parser(self, source, output, *options):
        return subprocess.run(
            [sys.executable, str(PARSER), str(source), str(output), *options],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_normal_log_special_characters_and_all_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "in"
            output = root / "out"
            make_log(source / "nested" / "normal.wua.log", "PC-01_20260909_100000")
            result = self.run_parser(source, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = {
                "systems.csv", "users.csv", "password_policies.csv", "interfaces.csv",
                "routes.csv", "firewall.csv", "netstat.csv", "ping.csv", "http.csv",
                "diagnostics.csv", "runs.csv", "parser_errors.csv",
            }
            self.assertEqual({path.name for path in output.iterdir()}, expected)
            users = read_csv(output / "users.csv")
            self.assertEqual(len(users), 2)
            header, row = users
            self.assertEqual(row[header.index("Имя")], "Антон")
            self.assertEqual(row[header.index("Описание")], 'Текст; с "кавычками"')
            self.assertEqual(row[header.index("Пусто")], "")
            diagnostics = read_csv(output / "diagnostics.csv")
            self.assertEqual(diagnostics[1][diagnostics[0].index("Сообщение")], "CR\rLF\nTAB\t")
            for path in output.iterdir():
                payload = path.read_bytes()
                self.assertTrue(payload.startswith(b"\xff\xfe"))
                self.assertNotIn(b"\r\x00\n\x00\r\x00\n\x00", payload)

    def test_incomplete_log_and_partial_are_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "in"
            make_log(source / "unfinished.wua.log", "PC-01_20260909_100000", end=False)
            make_log(source / "partial.wua.partial", "PC-02_20260909_100000", end=False)
            output_default = root / "default"
            self.assertEqual(self.run_parser(source, output_default).returncode, 0)
            self.assertEqual(len(read_csv(output_default / "users.csv")), 1)
            output_partial = root / "partial"
            self.assertEqual(self.run_parser(source, output_partial, "--all", "--include-partial").returncode, 0)
            self.assertEqual(len(read_csv(output_partial / "users.csv")), 3)
            runs = read_csv(output_partial / "runs.csv")
            self.assertEqual(len(runs), 3)
            self.assertTrue(all(row[runs[0].index("Наличие END")] == "Нет" for row in runs[1:]))

    def test_latest_uses_metadata_and_merges_schema_versions_without_shift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "in"
            make_log(
                source / "zzz_old.wua.log",
                "PC-01_old",
                start="2026-09-09T10:00:00+03:00",
                columns=["Идентификатор запуска", "A", "B"],
                values=["PC-01_old", "a1", "b1"],
            )
            make_log(
                source / "aaa_new.wua.log",
                "PC-01_new",
                start="2026-09-09T11:00:00+03:00",
                schema_version="2",
                columns=["Идентификатор запуска", "B", "C"],
                values=["PC-01_new", "b2", "c2"],
            )
            make_log(source / "other.wua.log", "PC-02_run", hostname="PC-02")
            output_all = root / "all"
            self.assertEqual(self.run_parser(source, output_all, "--all").returncode, 0)
            users = read_csv(output_all / "users.csv")
            header = users[0]
            self.assertLess(header.index("B"), header.index("C"))
            self.assertIn("A", header)
            old = next(row for row in users[1:] if row[header.index("Идентификатор запуска")] == "PC-01_old")
            new = next(row for row in users[1:] if row[header.index("Идентификатор запуска")] == "PC-01_new")
            self.assertEqual(old[header.index("C")], "Не определено")
            self.assertEqual(new[header.index("A")], "Не определено")
            self.assertEqual(new[header.index("B")], "b2")
            output_latest = root / "latest"
            self.assertEqual(self.run_parser(source, output_latest, "--latest").returncode, 0)
            latest = read_csv(output_latest / "users.csv")
            self.assertEqual(len(latest), 3)
            self.assertNotIn("PC-01_old", [row[latest[0].index("Идентификатор запуска")] for row in latest[1:]])
            runs = read_csv(output_latest / "runs.csv")
            reason_index = runs[0].index("Причина выбора или пропуска")
            self.assertIn("более поздний", next(row for row in runs[1:] if row[0] == "PC-01_old")[reason_index])

    def test_unknown_and_damaged_records_are_isolated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "in"
            extra = [
                ["WUA1", "SCHEMA", "FUTURE", "99", "X"],
                ["WUA1", "DATA", "FUTURE", "99", "x"],
                ["WUA1", "MYSTERY", "x"],
                ["WUA1", "DATA", "USER", "1", "too", "few"],
                ["WUA1", "DATA", "USER", "1", "too", "many", "fields", "here", "x"],
            ]
            make_log(source / "mixed.wua.log", "PC-01_run", extra_rows=extra)
            # Append an unmatched quote as a separate physical line.
            with (source / "mixed.wua.log").open("a", encoding="utf-16", newline="") as stream:
                stream.write('"WUA1";"DATA";"USER";"1";"broken\r\n')
            # A second valid file proves one bad file/line does not stop processing.
            make_log(source / "valid.wua.log", "PC-02_run", hostname="PC-02")
            output = root / "out"
            result = self.run_parser(source, output, "--all")
            self.assertEqual(result.returncode, 0, result.stderr)
            errors = read_csv(output / "parser_errors.csv")
            descriptions = "\n".join(row[5] for row in errors[1:])
            self.assertIn("Неизвестный тип DATA", descriptions)
            self.assertIn("Неизвестный вид записи", descriptions)
            self.assertIn("не совпадает со SCHEMA", descriptions)
            self.assertIn("Повреждённая CSV-строка", descriptions)
            users = read_csv(output / "users.csv")
            self.assertGreaterEqual(len(users), 3)

    def test_all_and_latest_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_parser(root, root / "out", "--all", "--latest")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not allowed", result.stderr)


if __name__ == "__main__":
    unittest.main()
