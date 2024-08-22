# Packet Analyzer

Packet Analyzer is a C program that captures and analyzes network packets using the libpcap library. It can read packets from a network interface or a pcap file, extract relevant information, and write the results to a text file.

## Features

- Capture packets from a network interface or read from a pcap file
- Extract MAC addresses, IP addresses, and port numbers
- Identify HTTP traffic and extract GET/POST requests, Host, and User-Agent information
- Multi-threaded design for efficient packet capture and processing
- Output results to a specified text file

## Requirements

- GCC compiler
- libpcap library
- POSIX-compliant system (Linux/Unix)

## Installation

1. Clone the repository:
   ``` bash
   git clone https://github.com/anassajaanan/packet-analyzer.git
   cd packet-analyzer
   ```

2. Compile the program:
   ```
   make
   ```

## Usage

The program can be run in two modes:

1. Capture from a network interface:
   ```
   ./packet_analyzer -i <interface_name> -o <output_file.txt>
   ```

2. Read from a pcap file:
   ```
   ./packet_analyzer -f <input_file.pcap> -o <output_file.txt>
   ```

Example:
```
./packet_analyzer -i eth0 -o captured_packets.txt
```

## Cleaning up

To remove object files:
```
make clean
```

To remove object files and the executable:
```
make fclean
```

To recompile the project:
```
make re
```
