# xytop - Combined System Monitor

A terminal-based monitoring tool that combines process monitoring, disk I/O tracking, and network traffic analysis in a single interface.

## Features

- Real-time CPU, memory, and swap usage monitoring
- Disk usage and I/O statistics
- Network traffic analysis with packet inspection
- Process listing with resource usage information
- Historical trends with simple graphs
- Clean, color-coded interface

## Requirements

- Python 3.6 or higher
- psutil (for system monitoring)
- scapy (for network packet analysis)
- curses (included in Python standard library)

## Installation

### From Debian Package

```bash
# Install the .deb package
sudo dpkg -i xytop_1.0.0_all.deb

# Install dependencies if needed
sudo apt-get install -f
```

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/xytop.git
cd xytop

# Install dependencies
sudo apt install python3-psutil python3-scapy

# Install the package
sudo python3 setup.py install
```

## Usage

Basic usage:

```bash
xytop
```

For full network analysis capabilities, run with sudo:

```bash
sudo xytop
```

### Controls

- `q` - Quit the application
- More key bindings coming in future versions

## Building the Debian Package

```bash
# Install build dependencies
sudo apt install debhelper dh-python python3-all python3-setuptools

# Build the package
dpkg-buildpackage -us -uc

# The .deb package will be created in the parent directory
```

## Screenshots

(Coming soon)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
