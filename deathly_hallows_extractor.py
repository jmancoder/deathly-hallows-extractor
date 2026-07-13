import argparse
import json
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
    header_off: int
    header_size: int
    payload_off: int
    payload_size: int
    child_id: int


class Asset(NamedTuple):
    payload_off: int
    payload_size: int
    category: str
    path: str
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

    def cache_entry(self, entry: ArchiveEntry) -> None:
        header_off = self.bs.tell()
        self.bs.seek(entry.header_size, 1)
        
        payload_off = self.bs.tell()
        self.bs.seek(entry.payload_size, 1)

        padding = (((entry.payload_size + 15) // 16) * 16) - entry.payload_size
        self.bs.seek(padding, 1)

        if ":" in entry.string:
            entry_category, entry_path = entry.string.split(":")
            if entry_category == self.archive_name:
                # Cache Deathly Hallows 1 chunk
                self.chunk_map[int(entry_path)] = Chunk(
                    header_off,
                    entry.header_size,
                    payload_off,
                    entry.payload_size,
                    entry.child_chunk_id
                )
            else:
                # Cache asset descriptor
                self.assets.append(Asset(
                    payload_off,
                    entry.payload_size,
                    entry_category,
                    entry_path,
                    entry.child_chunk_id,
                ))
        else:
            # Cache Deathly Hallows 2 chunk
            self.chunk_map[int(entry.string)] = Chunk(
                header_off,
                entry.header_size,
                payload_off,
                entry.payload_size,
                entry.child_chunk_id
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
                if ":" in chunk_string:
                    # Get Death Hallows 1 chunk ID
                    chunk_category, chunk_id_string = chunk_string.split(":")
                    if chunk_category != self.archive_name:
                        raise ValueError("Non-chunk child entries are not supported")
                    child_chunk_id = int(chunk_id_string)
                else:
                    # Get Death Hallows 2 chunk ID
                    child_chunk_id = int(chunk_string)
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
        
        # Cache internal entries
        external_entries = []
        for entry in self.entries:
            if entry.is_external:
                external_entries.append(entry)
            else:
                self.cache_entry(entry)
        
        # Cache external entries
        for entry in external_entries:
            self.cache_entry(entry)

    def export_manifest(self, out_dir: Path) -> None:
        manifest: dict = {}
        manifest["strings"] = self.string_map
        manifest["properties"] = self.property_strings
        manifest["assets"] = self.assets
        manifest["chunks"] = self.chunk_map

        with open(out_dir / f"manifest.json", "w") as f:
            json.dump(manifest, f, indent=4)

    def export_assets(self, out_dir: Path) -> None:
        exported_chunk_ids: list[int] = []
        for asset in self.assets:
            stored_path = Path(asset.path)
            asset_ext = "".join(stored_path.suffixes)
            asset_dir = out_dir / stored_path.parent
            os.makedirs(asset_dir, exist_ok=True)

            # Export inital payload if present
            if asset.payload_size > 0:
                out_info_name = f"{asset.category}_{stored_path.stem}_initial{asset_ext}"
                with open(asset_dir / out_info_name, "wb") as f:
                    self.bs.seek(asset.payload_off)
                    f.write(self.bs.read(asset.payload_size))

            i = 0
            chunk_id = asset.chunk_id
            while chunk_id != -1:
                chunk = self.chunk_map[chunk_id]
                exported_chunk_ids.append(chunk_id)
                
                # Export chunk header if present
                if chunk.header_size > 0:
                    out_chunk_header_name = f"{asset.category}_" \
                        f"{stored_path.stem}_chunk_{i}_header{asset_ext}"
                    with open(asset_dir / out_chunk_header_name, "wb") as f:
                        self.bs.seek(chunk.header_off)
                        f.write(self.bs.read(chunk.header_size))

                # Export chunk payload
                out_chunk_name = f"{asset.category}_{stored_path.stem}_chunk_{i}{asset_ext}"
                with open(asset_dir / out_chunk_name, "wb") as f:
                    self.bs.seek(chunk.payload_off)
                    f.write(self.bs.read(chunk.payload_size))

                chunk_id = chunk.child_id
                i += 1
        
        # Export unused chunks
        for chunk_id in self.chunk_map.keys():
            if chunk_id in exported_chunk_ids:
                continue
            
            chunk_dir = out_dir / "unused_chunks"
            os.makedirs(chunk_dir, exist_ok=True)
            with open(chunk_dir / str(chunk_id), "wb") as f:
                chunk = self.chunk_map[chunk_id]
                self.bs.seek(chunk.payload_off)
                f.write(self.bs.read(chunk.payload_size))


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

    reader.export_assets(out_dir)
    reader.export_manifest(out_dir)


if __name__ == "__main__":
    main()
