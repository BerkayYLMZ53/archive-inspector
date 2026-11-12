"""Inspect a ZIP file and report extraction hazards without extracting it."""

import argparse
import json
import lzma
import ntpath
from pathlib import Path
import re
import stat
import sys
import zipfile
import zlib


MIB = 1024 * 1024
WINDOWS_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])\Z", re.IGNORECASE)
WINDOWS_INVALID = re.compile(r'[<>:"|?*]')


def classify_name(name):
    # Backslashes also delimit ZIP paths in some Windows extractors.
    normalized = name.replace("\\", "/")
    components = [part for part in normalized.split("/") if part not in {"", "."}]
    findings = []
    if normalized.startswith("/") or ntpath.splitdrive(normalized)[0] or ".." in components:
        findings.append("unsafe-path")
    if not components or any(ord(character) < 32 or ord(character) == 127 for character in name):
        findings.append("invalid-name")
    if any(
        part != ".." and (
            part != part.rstrip(" .") or WINDOWS_INVALID.search(part)
            or WINDOWS_DEVICE.fullmatch(part.split(".", 1)[0].rstrip(" "))
        )
        for part in components
    ):
        findings.append("windows-name")
    key = tuple(part.rstrip(" .").casefold() for part in components)
    return key, findings


FINDING_LABELS = {
    "unsafe-path": "Arşiv dışına çıkabilen yol",
    "invalid-name": "Boş ad veya kontrol karakteri",
    "windows-name": "Windows için geçersiz veya özel ad",
    "path-collision": "Aynı hedefe yazılabilecek başka bir kayıt var",
    "file-parent": "Üst yol arşivde klasör yerine dosya olarak kayıtlı",
    "symlink": "Sembolik bağlantı",
    "special-file": "Normal dosya veya klasör olmayan kayıt",
    "encrypted": "Şifreli kayıt",
    "high-ratio": "Yüksek sıkıştırma oranı",
}


def inspect(archive, verify=False, max_bytes=256 * MIB):
    entries = []
    findings = []
    seen = set()
    files = set()
    by_key = []
    infos = archive.infolist()

    def flag(code, name):
        findings.append({"code": code, "name": name, "message": FINDING_LABELS[code]})

    for info in infos:
        name = info.orig_filename
        key, name_findings = classify_name(name)
        by_key.append((key, name))
        for code in name_findings:
            flag(code, name)
        if key in seen:
            flag("path-collision", name)
        seen.add(key)

        mode = (info.external_attr >> 16) if info.create_system == 3 else 0
        directory = info.is_dir() or stat.S_ISDIR(mode)
        if not directory:
            files.add(key)
        if stat.S_ISLNK(mode):
            flag("symlink", name)
        elif stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
            flag("special-file", name)
        encrypted = bool(info.flag_bits & 1)
        if encrypted:
            flag("encrypted", name)
        if info.file_size >= MIB and info.file_size >= 100 * max(info.compress_size, 1):
            flag("high-ratio", name)
        entries.append({
            "name": name, "kind": "directory" if directory else "file", "bytes": info.file_size,
            "compressed_bytes": info.compress_size, "encrypted": encrypted,
        })

    for key, name in by_key:
        if any(key[:length] in files for length in range(1, len(key))):
            flag("file-parent", name)

    total = sum(entry["bytes"] for entry in entries)
    status = {"status": "not-requested"}
    if verify:
        if total > max_bytes:
            status = {"status": "skipped", "reason": "Bildirilen açık boyut doğrulama sınırını aşıyor."}
        elif any(entry["encrypted"] for entry in entries):
            status = {"status": "skipped", "reason": "Şifreli kayıtlar bu araçla doğrulanamıyor."}
        else:
            # Open by ZipInfo so repeated member names are verified separately.
            consumed = 0
            for info in infos:
                with archive.open(info) as data:
                    while chunk := data.read(64 * 1024):
                        consumed += len(chunk)
                        if consumed > max_bytes:
                            raise ValueError("Okunan açık boyut doğrulama sınırını aştı.")
            status = {"status": "passed"}

    return {
        "entries": entries, "findings": findings, "uncompressed_bytes": total,
        "compressed_bytes": sum(entry["compressed_bytes"] for entry in entries),
        "verification": status,
    }


def positive_integer(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Pozitif bir tam sayı gir") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("Pozitif bir tam sayı gir")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="ZIP arşivini açmadan içeriğini ve olası yol sorunlarını inceler.")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--list", action="store_true", help="Arşivdeki her kaydı göster")
    parser.add_argument("--verify", action="store_true", help="Kayıtları belleğe akıtarak CRC bütünlüğünü denetle")
    parser.add_argument("--max-mib", type=positive_integer, default=256, help="CRC denetimi için açık boyut sınırı")
    parser.add_argument("--json", action="store_true", help="Raporu JSON olarak yaz")
    args = parser.parse_args(argv)

    try:
        with zipfile.ZipFile(args.archive) as archive:
            report = inspect(archive, args.verify, args.max_mib * MIB)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error, lzma.LZMAError) as error:
        print(f"Hata: {error}", file=sys.stderr)
        return 2

    verification = report["verification"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"{len(report['entries'])} kayıt, sıkıştırılmış {report['compressed_bytes']} bayt, "
            f"açık {report['uncompressed_bytes']} bayt."
        )
        if args.list:
            for entry in report["entries"]:
                print(f"  {entry['bytes']:>12}  {entry['name']!r}")
        for finding in report["findings"]:
            print(f"Bulgu: {finding['message']} ({finding['name']!r})")
        if verification["status"] == "passed":
            print("CRC denetimi başarılı.")
        elif verification["status"] == "skipped":
            print(f"CRC denetimi atlandı. {verification['reason']}")
    return int(bool(report["findings"]) or verification["status"] == "skipped")


if __name__ == "__main__":
    sys.exit(main())
