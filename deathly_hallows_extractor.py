import argparse
import os
import struct
import zlib

from io import BytesIO
from pathlib import Path
from typing import NamedTuple


class ArchiveEntry(NamedTuple):
    string: str
    chunk_string: str
    payload_size: int
    flags: int
    header_size: int
    is_external: bool
    unk_id_count: int
    unk_0: int
    unk_1: int
    unk_2: int


class Chunk(NamedTuple):
    payload: bytes
    child_string: str


class Asset(NamedTuple):
    category: str
    path: Path
    child_string: int


class ArchiveReader:
    def __init__(self) -> None:
        self.bs: BytesIO
        self.archive_name: str
        self.string_map: dict[int, str] = {}
        self.property_strings: list[str] = []
        self.entries: list[ArchiveEntry] = []
        self.assets: list[Asset] = []
        self.chunk_map: dict[str, Chunk] = {}
    
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

        if entry_category == "MSH":
            print(payload_start, entry)
            print()

        if entry_category == self.archive_name:
            self.chunk_map[int(entry_path)] = Chunk(payload, entry.chunk_id)
        elif entry.chunk_id != -1:
            # Read asset
            self.assets.append(Asset(entry_category,
                Path(entry_path), entry.chunk_id))
        else:
            pass
            #print("Uncategorized:", entry)


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
                entry_string = ""

            chunk_string_id = self.read_int32()
            if chunk_string_id >= 0:
                chunk_string = self.string_map[chunk_string_id]
                chunk_id = int(chunk_string.split(":")[1])
            else:
                chunk_id = -1

            self.entries.append(ArchiveEntry(
                entry_string,
                chunk_id,
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
            out_name = f"{asset.category}_{asset.path.name}"
            out_path = out_dir / asset.path.parent / out_name
            os.makedirs(out_path.parent, exist_ok=True)

            with open(out_path, "wb") as f:
                # Parse chunks and chunk redirectors additively
                # This is a stupid idea and will probably not work
                # cur_chunk = self.chunk_map[asset.chunk_id]
                # for i in range(REDIRECT_LIMIT):
                #     if cur_chunk.child_chunk_id == -1:
                #         f.write(cur_chunk.payload)
                #         break
                #     else:
                #         # Skip payload of first redirector?
                #         if i > 0:
                #             f.write(cur_chunk.payload)
                #         cur_chunk = self.chunk_map[cur_chunk.child_chunk_id]
                # else:
                #     print("Warning: Redirect limit reached.")

                # Write a single chunk for now, ignoring its child ID
                f.write(self.chunk_map[asset.chunk_id].payload)

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
