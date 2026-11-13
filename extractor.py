import argparse
from dataclasses import dataclass
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import struct
import zlib


@dataclass(slots=True)
class Entry:
    name_id: int
    child_id: int
    payload_size: int
    flags: int
    header_size: int
    is_external: int
    unk_int_count: int
    unk_0: int
    unk_1: int
    unk_2: int


class ArchiveExtractor:
    def __init__(self) -> None:
        self.bs: BytesIO
        self.archive_name: str
        self.string_map: dict[int, str] = {}
        self.property_ids: list[int] = []
        self.entries: list[Entry] = []
        self.unk_int_groups: list[list[int]] = []

    def read_string(self, offset_limit: int) -> str:
        out_str = StringIO()
        while self.bs.tell() < offset_limit:
            c = self.bs.read(1)[0]
            if c == 0:
                break
            else:
                out_str.write(chr(c))
        return out_str.getvalue()

    def read_int32(self) -> int:
        return int.from_bytes(self.bs.read(4), "little", signed=True)

    def read_uint32(self) -> int:
        return int.from_bytes(self.bs.read(4), "little")

    def _export_asset(self, entry: Entry, out_dir: Path):
        name = self.string_map[entry.name_id]
        if ":" in name:
            category, path = name.split(":")
        else:
            category = self.archive_name
            path = name

        if category == self.archive_name:
            out_path = out_dir / path
        else:
            # Create subfolders and add category as extension
            out_path = out_dir / f"{path}.{category}"
            os.makedirs(out_path.parent, exist_ok=True)

        # Export header and aligned payload
        with open(out_path, "wb") as f:
            f.write(self.bs.read(entry.header_size))
            f.write(self.bs.read(entry.payload_size))
            self.bs.seek(
                (((entry.payload_size + 15) // 16) * 16) - entry.payload_size, 1
            )

    def export_assets(self, out_dir: Path) -> None:
        external_entries: list[Entry] = []
        for entry in self.entries:
            if entry.is_external:
                external_entries.append(entry)
                continue
            self._export_asset(entry, out_dir)
        for entry in external_entries:
            self._export_asset(entry, out_dir)

    def export_manifest(self, out_dir: Path) -> None:
        json_entry_map: dict[int, dict] = {}
        for entry in self.entries:
            json_entry = {}
            json_entry["child_id"] = entry.child_id
            json_entry["payload_size"] = entry.payload_size
            json_entry["flags"] = entry.flags
            json_entry["header_size"] = entry.header_size
            json_entry["is_external"] = entry.is_external
            json_entry["unk_int_count"] = entry.unk_int_count
            json_entry["unk_0"] = entry.unk_0
            json_entry["unk_1"] = entry.unk_1
            json_entry["unk_2"] = entry.unk_2
            json_entry_map[entry.name_id] = json_entry

        with open(out_dir / "manifest.json", "wt") as f:
            manifest = {
                "strings": self.string_map,
                "chunks": json_entry_map,
                "property_ids": self.property_ids,
                "unk_int_groups": self.unk_int_groups,
            }
            json.dump(manifest, f, indent=4)

    def load_archive(self, name: str, data: bytes) -> None:
        self.bs = BytesIO(data)
        self.archive_name = name

        # Read global string table
        string_block_end = self.read_uint32() + 4
        string_count = self.read_uint32()
        for _ in range(string_count):
            string_id = self.read_uint32()
            self.string_map[string_id] = self.read_string(string_block_end)
        self.bs.seek(string_block_end)

        # Read property IDs
        property_count = self.read_uint32()
        self.property_ids = [self.read_uint32() for _ in range(property_count)]

        # Read entries
        entry_count = self.read_uint32()
        for _ in range(entry_count):
            self.entries.append(Entry(*struct.unpack("<10i", self.bs.read(40))))

        # Read unknown int groups
        for entry in self.entries:
            self.unk_int_groups.append(
                [self.read_int32() for _ in range(entry.unk_int_count)]
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "in_path", type=Path, help="path to the .bin.gz archive to extract"
    )
    parser.add_argument(
        "out_dir", type=Path, help="path to a folder to extract the archive into"
    )
    args = parser.parse_args()

    in_path = Path(args.in_path)
    archive_name = in_path.name.split(".")[0]

    out_dir = Path(args.out_dir) / archive_name
    os.makedirs(out_dir, exist_ok=True)

    # Read and extract assets from the archive
    extractor = ArchiveExtractor()
    with open(in_path, "rb") as f:
        extractor.load_archive(archive_name, zlib.decompress(f.read()))
    extractor.export_assets(out_dir)
    extractor.export_manifest(out_dir)


if __name__ == "__main__":
    main()
