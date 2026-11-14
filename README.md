# Deathly Hallows Extractor
A Python script for extracting .bin.gz archives from Harry Potter and the Deathly Hallows – Part 1 and Harry Potter and the Deathly Hallows – Part 2. Only the PC versions have been tested. You can use [this](https://github.com/jmancoder/io-deathly-hallows) Blender extension to import the extracted assets.

## Usage
```bash
python extractor.py [path to .bin.gz file] [path to empty output folder]
```
A manifest.json file will be created in the output files. You can use this to read the string table and see information about each chunk.
