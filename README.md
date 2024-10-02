# Northwind
Yet another tcpdump.
Northwind is a modern re-implementation of tcpdump, a powerful command-line packet analyzer tool. This project aims to provide a lightweight, efficient, and user-friendly tool for capturing and analyzing network traffic, leveraging updated technologies and enhancements.

## Table of contents
- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Building from source](#building-from-source)
- [Contributing](#contributing)

## About
`Northwind` aims to re-implement the core functionality of `tcpdump` with additional modern enhancements such as:

- Improved performance with optimized packet capturing.
- Customizable and user-friendly output formats.
- Extensibility for additional protocols.

`tcpdump` is widely used for debugging network issues, capturing and analyzing network packets, and performing security analysis. With `Northwind`, we aim to provide a fresh, efficient, and easier-to-use alternative that fits into modern networking workflows.

## Features
- **Packet capturing**: Capture network packets from a specified network interface.
- **Filtering**: Filter packets based on various criteria such as source/destination IP, port, protocol, etc.
- **Protocol analysis**: Analyze packets based on various network protocols (e.g., TCP, UDP, ICMP).
- **Real-time monitoring**: Monitor network traffic in real-time with customizable output options.
- **Extensible**: Designed for modularity, allowing for easy integration of new protocols and features.

## Installation
### Prerequisites
- A C compiler (GCC or clang)
- `libpcap` a library for packet capture
- Git (for cloning the repository)

### Steps
1. Clone the repository:
```bash
git clone https://github.com/drakrn/northwind.git
```

2. Navigate to the project directory:
```bash
cd northwind
```

3. Build the project:
```bash
make
```

4. Run the binary (once built):
```bash
./northwind
```

5. Export the binary to your PATH (optional):
```bash
sudo cp northwind /usr/local/bin
```

## Usage
`Northwind` captures and analyzes network traffic in real-time. Below are some examples of basic usage.

### Capture packet on a specific interface
```bash
```

### Filter traffic by host:
```bash
```

### Filter traffic by port:
```bash
```

### Capture only TCP packets:
```bash
```

### Display verbose output:
```bash
```

For a full list of options, use the `--help` flag:
```bash
```

## Building from source
To build `Northwind` from source, follow the steps below:
### 1. Prerequisites
- **C compiler**: Ensure you have a C compiler such as GCC or Clang.
- **libpcap**: Install the `libpcap` library for packet capture. 

**Linux:**
Install `libpcap` with your package manager:
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel

# Arch Linux
sudo pacman -S libpcap
```

**macOS:**
Use Homebrew to install `libpcap`:
```bash
brew install libpcap
```

### 2. Building
Once all dependencies are installed, you can build the project:
```bash
make
```
This will compile the project and place the binary output in the `bin/` directory.

## Contributing
We welcome contributions from the community! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Submit a pull request with a detailed description of the changes.