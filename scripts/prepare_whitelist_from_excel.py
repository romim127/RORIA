from __future__ import annotations

import argparse
import csv
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


NS = {
    "a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}

IMEI_COLUMNS = ("IMEI", "IMEI1", "IMEI2", "IMEI3")
IMEI_FALLBACK_COLUMNS = ("NroTelefono",)


def _colnum(ref: str) -> int:
    match = re.match(r"([A-Z]+)", ref or "")
    value = 0
    for char in match.group(1) if match else "":
        value = value * 26 + ord(char) - 64
    return value


def _read_first_sheet(path: Path) -> list[dict[str, str]]:
    with zipfile.ZipFile(path) as archive:
        shared: list[str] = []
        try:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.findall("a:si", NS):
                shared.append("".join(t.text or "" for t in item.findall(".//a:t", NS)))
        except KeyError:
            pass

        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        relmap = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels}
        sheet = workbook.find("a:sheets/a:sheet", NS)
        if sheet is None:
            return []
        rel_id = sheet.attrib["{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"]
        sheet_xml = "xl/" + relmap[rel_id].lstrip("/")
        root = ET.fromstring(archive.read(sheet_xml))

        raw_rows: list[list[str]] = []
        for row in root.findall(".//a:sheetData/a:row", NS):
            values: dict[int, str] = {}
            for cell in row.findall("a:c", NS):
                index = _colnum(cell.attrib.get("r", ""))
                value_node = cell.find("a:v", NS)
                text = "" if value_node is None else (value_node.text or "")
                if cell.attrib.get("t") == "s" and text:
                    text = shared[int(text)]
                values[index] = text.strip()
            if values:
                raw_rows.append([values.get(i, "") for i in range(1, max(values) + 1)])

    if not raw_rows:
        return []
    header = raw_rows[0]
    return [
        {header[i]: row[i] if i < len(row) else "" for i in range(len(header))}
        for row in raw_rows[1:]
    ]


def _digits(value: object) -> str:
    return re.sub(r"\D+", "", str(value or ""))


def _description(row: dict[str, str], source_col: str) -> str:
    person = " ".join(
        part for part in [row.get("apellidos", "").strip(), row.get("nombres", "").strip()] if part
    )
    pieces = [
        person,
        row.get("jerarquia", "").strip(),
        row.get("area", "").strip(),
        row.get("complejo_nueva_denominacion", "").strip(),
        f"{row.get('marca', '').strip()} {row.get('modelo', '').strip()}".strip(),
        f"columna:{source_col}",
    ]
    return " | ".join(piece for piece in pieces if piece)


def prepare(input_path: Path, output_path: Path, rejected_path: Path) -> tuple[int, int]:
    rows = _read_first_sheet(input_path)
    valid: dict[str, dict[str, str]] = {}
    rejected: list[dict[str, str]] = []

    for row in rows:
        for column in (*IMEI_COLUMNS, *IMEI_FALLBACK_COLUMNS):
            raw = row.get(column, "").strip()
            if not raw:
                continue
            digits = _digits(raw)
            person = " ".join(
                part for part in [row.get("apellidos", "").strip(), row.get("nombres", "").strip()] if part
            )
            if len(digits) == 15:
                valid.setdefault(
                    digits,
                    {
                        "device_id": digits,
                        "device_type": "imei",
                        "description": _description(row, column),
                    },
                )
            elif column in IMEI_COLUMNS:
                rejected.append(
                    {
                        "source_column": column,
                        "raw_value": raw,
                        "digits_only": digits,
                        "digits_length": str(len(digits)),
                        "person": person,
                        "phone": _digits(row.get("NroTelefono", "")),
                        "area": row.get("area", "").strip(),
                    }
                )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    rejected_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=["device_id", "device_type", "description"])
        writer.writeheader()
        writer.writerows(sorted(valid.values(), key=lambda item: item["device_id"]))

    with rejected_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["source_column", "raw_value", "digits_only", "digits_length", "person", "phone", "area"],
        )
        writer.writeheader()
        writer.writerows(rejected)

    return len(valid), len(rejected)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepara CSV de lista blanca desde XLSX de RRHH.")
    parser.add_argument("input", type=Path, help="Archivo .xlsx original")
    parser.add_argument("--output", type=Path, default=Path("whitelist_clean.csv"))
    parser.add_argument("--rejected", type=Path, default=Path("whitelist_rejected.csv"))
    args = parser.parse_args()

    valid_count, rejected_count = prepare(args.input, args.output, args.rejected)
    print(f"IMEI validos exportados: {valid_count}")
    print(f"Valores rechazados para revisar: {rejected_count}")
    print(f"CSV limpio: {args.output}")
    print(f"CSV rechazados: {args.rejected}")


if __name__ == "__main__":
    main()
