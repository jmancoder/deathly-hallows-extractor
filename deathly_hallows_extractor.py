import argparse
from dataclasses import dataclass
from io import BytesIO
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


@dataclass(slots=True)
class Chunk:
    parent_id: int
    child_id: int
    header_off: int
    header_size: int
    payload_off: int
    payload_size: int


class ArchiveExtractor:
    def __init__(self) -> None:
        self.bs: BytesIO
        self.archive_name: str
        self.string_map: dict[int, str] = {}
        self.property_ids: list[int] = []
        self.entries: list[Entry] = []
        self.chunk_map: dict[int, Chunk] = {}

    def read_string(self, offset_limit: int) -> str:
        out_chars = []
        while self.bs.tell() < offset_limit:
            c = self.bs.read(1)[0]
            if c == 0:
                break
            else:
                out_chars.append(chr(c))
        return "".join(out_chars)

    def read_int32(self) -> int:
        return struct.unpack("<i", self.bs.read(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self.bs.read(4))[0]

    def skip_and_add_chunk(self, entry: Entry) -> None:
        header_off = self.bs.tell()
        self.bs.seek(entry.header_size, 1)
        payload_off = self.bs.tell()
        self.bs.seek(entry.payload_size, 1)
        padding = (((entry.payload_size + 15) // 16) * 16) - entry.payload_size
        self.bs.seek(padding, 1)

        self.chunk_map[entry.name_id] = Chunk(
            -1,
            entry.child_id,
            header_off,
            entry.header_size,
            payload_off,
            entry.payload_size,
        )

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

        # Skip unknown int groups
        for entry in self.entries:
            self.bs.seek(entry.unk_int_count * 4, 1)

        # Skip entry payloads and store offsets in chunk map
        external_entries = []
        for entry in self.entries:
            if entry.is_external:
                external_entries.append(entry)
            else:
                self.skip_and_add_chunk(entry)
        for entry in external_entries:
            self.skip_and_add_chunk(entry)

        # Update chunk parent IDs
        for chunk_id, chunk in self.chunk_map.items():
            if chunk.child_id > -1:
                self.chunk_map[chunk.child_id].parent_id = chunk_id

    def export_assets(self, out_dir: Path, merge_chunks: bool) -> None:
        for chunk_id, chunk in self.chunk_map.items():
            # If merging chunks, only create files for root assets
            if merge_chunks and chunk.parent_id != -1:
                continue

            # Create path and subfolders
            category, path = self.string_map[chunk_id].split(":")
            if category == self.archive_name:
                out_path = out_dir / path
            else:
                out_path = out_dir / Path(path)
                os.makedirs(out_path.parent, exist_ok=True)

            with open(out_path, "wb") as f:
                # Write chunk, except on textures where it is a redundant header
                if (not merge_chunks) or (merge_chunks and category != "TEX"):
                    self.bs.seek(chunk.payload_off)
                    f.write(self.bs.read(chunk.payload_size))

                # Write child chunks
                if merge_chunks and chunk.child_id > -1:
                    child_chunk = self.chunk_map[chunk.child_id]
                    while True:
                        self.bs.seek(child_chunk.payload_off)
                        f.write(self.bs.read(child_chunk.payload_size))

                        if child_chunk.child_id > -1:
                            child_chunk = self.chunk_map[child_chunk.child_id]
                        else:
                            break

    def export_manifest(self, out_dir: Path) -> None:
        json_chunks: list[dict] = []
        for chunk_id, chunk in self.chunk_map.items():
            json_chunk = {}
            json_chunk["name"] = self.string_map[chunk_id]
            json_chunk["parent_name"] = (
                self.string_map[chunk.parent_id] if chunk.parent_id > -1 else None
            )
            json_chunk["child_name"] = (
                self.string_map[chunk.child_id] if chunk.child_id > -1 else None
            )
            json_chunk["header_offset"] = chunk.header_off
            json_chunk["header_size"] = chunk.header_size
            json_chunk["payload_offset"] = chunk.payload_off
            json_chunk["payload_size"] = chunk.payload_size
            json_chunks.append(json_chunk)

        with open(out_dir / "manifest.json", "wt") as f:
            json.dump({"strings": self.string_map, "chunks": json_chunks}, f, indent=4)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "in_path", type=Path, help="path to the .bin.gz archive to extract"
    )
    parser.add_argument(
        "out_dir", type=Path, help="path to a folder to extract the archive into"
    )
    parser.add_argument(
        "-s",
        "--split-chunks",
        action="store_true",
        help="avoids merging child and parent chunks",
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
    extractor.export_assets(out_dir, not args.split_chunks)
    extractor.export_manifest(out_dir)


if __name__ == "__main__":
    main()
