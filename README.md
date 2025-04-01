# iOS Triangulation Detector

This tool is a modified version of Kaspersky's [triangle_check](https://github.com/KasperskyLab/triangle_check) that works with full iOS filesystem images rather than just iTunes backups.

## Purpose

The original triangle_check tool is designed to detect traces of the Operation Triangulation malware in iOS devices, but it only works with iTunes/Finder backups. This modified version can analyze full filesystem images, making it useful for digital forensics investigators working with complete device images.

## Key Differences from Original Tool

1. Works with full iOS filesystem paths (`/private/var/mobile/...`) rather than iTunes backup relative paths
2. No need for decryption handling (full filesystem images are already decrypted)
3. Directly analyzes files in their original locations

## Features

- Detects suspicious file system modifications in SMS attachment directories
- Identifies unusual patterns with location services
- Checks for suspicious network activity
- Uses the same detection logic as the original triangle_check tool

## Usage

```
python -m ios_triangulation_detector /path/to/mounted_ios_image
```

## Requirements

- Python 3.6+
- pycrypto
- colorama

## Installation

```
pip install -r requirements.txt
```

## Credit

This tool is based on Kaspersky's triangle_check tool, which is copyright © 2023 AO Kaspersky Lab. All Rights Reserved.
