import argparse
import os
import struct
import zlib

from io import BytesIO
from pathlib import Path
from typing import NamedTuple


class ArchiveEntry(NamedTuple):
    string: str
    child_chunk_id: int
    payload_size: int
    flags: int
    header_size: int
    is_external: bool
    unk_id_count: int
    unk_0: int
    unk_1: int
    unk_2: int


class Chunk(NamedTuple):
    header_payload: bytes
    payload: bytes
    child_id: int


class Asset(NamedTuple):
    initial_payload: bytes
    category: str
    path: Path
    chunk_id: int


class ArchiveReader:
    def __init__(self) -> None:
        self.bs: BytesIO
        self.archive_name: str
        self.string_map: dict[int, str] = {}
        self.property_strings: list[str] = []
        self.entries: list[ArchiveEntry] = []
        self.assets: list[Asset] = []
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

    def read_entry_payload(self, entry: ArchiveEntry) -> None:
        payload_start = self.bs.tell()
        header = self.bs.read(entry.header_size)
        payload = self.bs.read(entry.payload_size)
        padding = (((entry.payload_size + 15) // 16) * 16) - entry.payload_size
        self.bs.seek(padding, 1)

        entry_category, entry_path = entry.string.split(":")
        if entry_category == self.archive_name:
            self.chunk_map[int(entry_path)] = Chunk(
                header,
                payload,
                entry.child_chunk_id
            )
        else:
            self.assets.append(Asset(
                payload,
                entry_category,
                Path(entry_path),
                entry.child_chunk_id,
            ))


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
    
        # Read property strings by ID
        property_count = self.read_uint32()
        self.property_strings = [
            self.string_map[self.read_uint32()]
            for _ in range(property_count)
        ]

        # Read entries
        entry_count = self.read_uint32()
        for _ in range(entry_count):
            string_id = self.read_int32()
            if string_id >= 0:
                entry_string = self.string_map[string_id]
            else:
                raise ValueError("Entry string ID cannot be negative")

            # Retrieve entry chunk ID
            chunk_string_id = self.read_int32()
            if chunk_string_id >= 0:
                chunk_string = self.string_map[chunk_string_id]
                chunk_category, chunk_id_string = chunk_string.split(":")
                if chunk_category != self.archive_name:
                    raise ValueError("Non-chunk child entries are not supported")
                child_chunk_id = int(chunk_id_string)
            else:
                child_chunk_id = -1

            self.entries.append(ArchiveEntry(
                entry_string,
                child_chunk_id,
                *struct.unpack("<8i", self.bs.read(32))
            ))

        # Skip unknown integer groups
        for entry in self.entries:
            self.bs.seek(entry.unk_id_count * 4, 1)
        
        # Read internal payloads
        external_entries = []
        for entry in self.entries:
            if entry.is_external:
                external_entries.append(entry)
            else:
                self.read_entry_payload(entry)
        
        # Read external payloads
        for entry in external_entries:
            self.read_entry_payload(entry)


    def extract_assets(self, out_dir: Path) -> None:
        for asset in self.assets:
            asset_ext = "".join(asset.path.suffixes)
            asset_dir = out_dir / asset.path.parent
            os.makedirs(asset_dir, exist_ok=True)

            # Write inital payload if present
            if asset.initial_payload:
                out_info_name = f"{asset.category}_{asset.path.stem}_initial{asset_ext}"
                with open(asset_dir / out_info_name, "wb") as f:
                    f.write(asset.initial_payload)

            i = 0
            chunk_id = asset.chunk_id
            while chunk_id != -1:
                chunk = self.chunk_map[chunk_id]
                
                # Write chunk header if present
                if chunk.header_payload:
                    out_chunk_header_name = f"{asset.category}_" \
                        f"{asset.path.stem}_chunk_header{i}{asset_ext}"
                    with open(asset_dir / out_chunk_header_name, "wb") as f:
                        f.write(chunk.header_payload)

                # Write chunk payload
                out_chunk_name = f"{asset.category}_{asset.path.stem}_chunk_{i}{asset_ext}"
                with open(asset_dir / out_chunk_name, "wb") as f:
                    f.write(chunk.payload)

                chunk_id = chunk.child_id
                i += 1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("in_path", type=Path,
        help="path to the .bin.gz archive to extract")
    parser.add_argument("out_dir", type=Path,
        help="path to a folder to extract the archive into")
    args = parser.parse_args()

    # Create output folder
    in_path = Path(args.in_path)
    out_dir = Path(args.out_dir)
    archive_name = in_path.name.split(".")[0]
    out_dir = out_dir / archive_name
    os.makedirs(out_dir, exist_ok=True)

    # Read and extract assets from the archive
    reader = ArchiveReader()
    with open(in_path, "rb") as f:
        reader.load_archive(archive_name, zlib.decompress(f.read()))
    reader.extract_assets(out_dir)


if __name__ == "__main__":
    main()
