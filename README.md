# PyVault

**PyVault** is a command-line interface (CLI) tool designed for securely encrypting files using strong encryption methods. It's perfect for protecting sensitive data, making it an essential tool for personal use.

## Features

- **AES Encryption** - Industry-standard encryption via Fernet (AES-128-CBC + HMAC)
- **Graphical Interface** - Modern file explorer-style GUI with thumbnail previews
- **Embedded Thumbnails** - Automatic thumbnail generation for images and videos
- **Versioned Container Format** - Forward-compatible `.enc` file structure
- **Backward Compatible** - Seamlessly decrypts files from older versions
- **Progress Tracking** - Visual progress bar for large file operations

### Supported Thumbnail Formats

| Type | Extensions |
|------|------------|
| Images | `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.bmp` |
| Videos | `.mp4`, `.mov`, `.mkv`, `.avi`, `.webm` |

> **Note:** Video thumbnails require [FFmpeg](https://ffmpeg.org/) to be installed and available in PATH.

## Installation

```bash
pip install pyvault
```

### Dependencies

- Python 3.11+
- cryptography
- Pillow (for image thumbnails)
- PyQt6 (for GUI)
- FFmpeg (optional, for video thumbnails)

## Usage

### Initialization

First, initialize the application in the target folder:

```bash
vault init .
```

This creates a `config.json` file required for encryption/decryption.

> [!CAUTION]
> Do not delete the `config.json` file. It is required for decryption along with your password. Without it, decryption will be impossible.

### Encrypting Files

```bash
vault encrypt
```

You will be prompted to enter and confirm your password. To skip the prompt:

```bash
vault encrypt -k <your-password>
```

### Decrypting Files

```bash
vault decrypt
```

Or with password flag:

```bash
vault decrypt -k <your-password>
```

### Excluding Files

To exclude specific files from encryption:

```bash
vault exclude
```

This opens an interactive selector. To list currently excluded files:

```bash
vault exclude -l
```

### Graphical Interface

Launch the modern GUI for visual file management:

```bash
vault gui
```

The GUI provides:
- 📁 File explorer-style grid view with thumbnails
- 🔍 Search and filter by filename or extension
- ✅ Multi-select with Ctrl/Shift click
- 🔓 Batch decrypt selected files

### Version

```bash
vault --version
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `vault init [PATH]` | Initialize a new vault (default: `./vault`) |
| `vault encrypt [-k KEY]` | Encrypt all unencrypted files |
| `vault decrypt [-k KEY]` | Decrypt all encrypted files |
| `vault exclude [-l]` | Manage excluded files |
| `vault gui` | Launch the graphical interface |
| `vault --version` | Show version information |
| `vault --help` | Show help message |

## Technical Details

### Container Format (v3)

PyVault v0.3.0 introduces a new versioned binary container format:

```
┌─────────────────────────────────────────┐
│ HEADER (48 bytes)                       │
│ - Magic bytes: "ENCF"                   │
│ - Version: 3                            │
│ - Flags (thumbnail, media type)         │
│ - Section offsets and sizes             │
├─────────────────────────────────────────┤
│ SECTIONS                                │
│ - Salt (for key derivation)             │
│ - Encrypted Thumbnail (optional)        │
│ - Encrypted Filename                    │
│ - Encrypted Data                        │
└─────────────────────────────────────────┘
```

### Security

- **Key Derivation:** PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Encryption:** Fernet (AES-128-CBC with HMAC-SHA256)
- **Salt:** 16 bytes random per vault

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
