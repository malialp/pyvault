# PyVault

**PyVault** is a secure file encryption tool with both CLI and modern GUI interfaces. Built with strong encryption standards, it protects your sensitive files while providing an intuitive user experience with thumbnail previews and visual file management.

## Features

### Core
- **AES Encryption** - Industry-standard encryption via Fernet (AES-128-CBC + HMAC)
- **Versioned Container Format** - Forward-compatible `.enc` file structure
- **Backward Compatible** - Seamlessly decrypts files from older versions
- **Encrypted Filenames** - Original filenames are encrypted within the container

### Graphical Interface
- **Modern File Explorer** - Grid-based file browser with thumbnail previews
- **Zoom Control** - Adjustable card sizes with slider for comfortable viewing
- **Smart Thumbnails** - Automatic thumbnail generation for images and videos
- **Virtualized Layout** - Smooth performance even with thousands of files
- **Lazy Loading** - Thumbnails load on-demand as you scroll
- **Multi-Select** - Batch operations with Ctrl/Shift click support
- **Search & Filter** - Quick filtering by filename or extension

### Performance
- **LRU Thumbnail Cache** - Frequently accessed thumbnails are cached in memory
- **Buffered I/O** - Optimized file reading/writing for large files
- **HKDF Key Derivation** - Fast context-specific key generation
- **Background Workers** - Non-blocking UI during file operations

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

| Package | Purpose |
|---------|---------|
| Python 3.11+ | Runtime |
| cryptography | Encryption operations |
| Pillow | Image thumbnail generation |
| PyQt6 | Graphical user interface |
| FFmpeg | Video thumbnails (optional) |

## Quick Start

### 1. Initialize a Vault

```bash
vault init .
```

This creates a `config.json` file in the target directory.

> [!CAUTION]
> Do not delete the `config.json` file. It contains the salt required for key derivation. Without it, decryption will be impossible even with the correct password.

### 2. Encrypt Your Files

```bash
vault encrypt
```

Or with password flag to skip the prompt:

```bash
vault encrypt -k <your-password>
```

### 3. Decrypt Your Files

```bash
vault decrypt
```

Or with password flag:

```bash
vault decrypt -k <your-password>
```

## Graphical Interface

Launch the GUI for visual file management:

```bash
vault gui
```

### GUI Features

| Feature | Description |
|---------|-------------|
| **Grid View** | File explorer-style layout with thumbnail previews |
| **Zoom Slider** | Adjust card sizes from compact to large view |
| **Search Bar** | Filter files by name or extension |
| **Multi-Select** | Select multiple files with Ctrl+Click or Shift+Click |
| **Context Menu** | Right-click for quick actions |
| **Batch Decrypt** | Decrypt multiple selected files at once |
| **Progress Indicator** | Visual feedback during operations |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+A` | Select all files |
| `Ctrl+Click` | Toggle selection |
| `Shift+Click` | Range selection |
| `Delete` | Decrypt selected files |
| `Escape` | Clear selection |

## CLI Commands

| Command | Description |
|---------|-------------|
| `vault init [PATH]` | Initialize a new vault (default: current directory) |
| `vault encrypt [-k KEY]` | Encrypt all unencrypted files |
| `vault decrypt [-k KEY]` | Decrypt all encrypted files |
| `vault exclude [-l]` | Manage excluded files interactively |
| `vault gui` | Launch the graphical interface |
| `vault --version` | Show version information |
| `vault --help` | Show help message |

### Excluding Files

To exclude specific files from encryption:

```bash
vault exclude
```

This opens an interactive selector. To list currently excluded files:

```bash
vault exclude -l
```

## Technical Details

### Container Format (v3)

PyVault uses a versioned binary container format for encrypted files:

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

| Component | Implementation |
|-----------|----------------|
| **Key Derivation** | PBKDF2-HMAC-SHA256 with 480,000 iterations |
| **Encryption** | Fernet (AES-128-CBC with HMAC-SHA256) |
| **Salt** | 16 bytes random per vault |
| **Key Separation** | HKDF for deriving context-specific keys |

### Architecture

```
pyvault/
├── cli.py          # Command-line interface
├── vault.py        # Core vault operations
├── crypto.py       # Encryption/decryption logic
├── container.py    # Binary container format handling
├── thumbnail.py    # Thumbnail extraction service
└── gui/
    ├── main_window.py    # Main application window
    ├── file_grid.py      # Virtualized file grid
    ├── file_card.py      # Individual file card widget
    └── workers.py        # Background worker threads
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
