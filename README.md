# Network Device Scanner

A simple Go-based network scanner that discovers devices on your local network using ARP (Address Resolution Protocol) requests.

## Description

This tool scans your local network and displays:
- Available network interfaces
- Your current network configuration
- Active devices on the network with their:
  - IP addresses
  - MAC addresses
  - Device count

## Prerequisites

- Go 1.16 or later
- libpcap development files
  ```bash
  # macOS
  brew install libpcap

  # Ubuntu/Debian
  sudo apt-get install libpcap-dev

  # CentOS/RHEL
  sudo yum install libpcap-devel
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone [your-repo-url]
   cd wifi_scanner
   ```

2. Initialize Go module and install dependencies:
   ```bash
   go mod init wifi_scanner
   go get github.com/google/gopacket
   go mod tidy
   ```

## Usage

Run the scanner with sudo privileges (required for network access):

