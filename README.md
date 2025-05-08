# CodeAlpha_Project

interneship projects

# the first project Packet Analyzer - First Cybersecurity Internship Project

## Introduction

This project, a packet analyzer, represents my first undertaking as a cybersecurity intern at CodeAlpha. It's a Python-based tool designed to capture and decode network packets, providing insights into network traffic by dissecting various protocol headers. This tool allows for the analysis of Ethernet, IP, TCP, UDP, and ICMP packets.

## Project Goals

- Gain practical experience in network packet analysis.
- Understand the structure of common network protocols.
- Develop skills in socket programming and binary data manipulation.
- Apply cybersecurity principles to network traffic monitoring.
- Demonstrate the ability to build a functional network analysis tool.

## Features

- **Packet Capture:** Captures network packets using a raw socket.
- **Header Decoding:** Decodes the headers of the following protocols:
  - Ethernet
  - IP (Internet Protocol)
  - TCP (Transmission Control Protocol)
  - UDP (User Datagram Protocol)
  - ICMP (Internet Control Message Protocol)
- **Header Information Display:** Prints detailed information about each decoded header, including source and destination addresses, ports, checksums, and other relevant fields.
- **Interface Selection:** Allows the user to specify a network interface to listen on, or listen on all interfaces if none is specified.
- **Clear Output:** Presents the analyzed packet data in a human-readable format.

## Technologies Used

- **Python:** The primary programming language.
- **`socket`:** For creating raw sockets and capturing network packets.
- **`struct`:** For unpacking binary data from packet headers.
- **`collections.namedtuple`:** For creating structured representations of header data.
- **`sys`:** For accessing command-line arguments.

## Prerequisites

- **Python 3.x:** This code is written for Python 3.
- **Root Privileges:** Running this script requires root privileges (using `sudo`) due to the use of raw sockets.
- **Linux Environment:** While potentially adaptable, this code was developed and tested on a Linux environment.

## Installation and Usage

1.  **Clone the repository:**

    ```bash
    git clone [repository URL]
    cd [repository directory]
    ```

2.  **Run the script:**

    - **To listen on all interfaces:**

      ```bash
      sudo python packet_analyzer.py
      ```

    - **To listen on a specific interface (e.g., `eth0`):**
      ```bash
      sudo python packet_analyzer.py eth0
      ```

    Replace `eth0` with the name of your desired network interface. Use `ifconfig` or `ip addr` to find the available interfaces.

## Example Output

The output will display the decoded headers of captured packets. Here's a snippet of what you might see:

Sniffing packets on interface: eth0...

Ethernet Header:
Destination MAC: 00:11:22:33:44:55
Source MAC: aa:bb:cc:dd:ee:ff
Protocol Type: 2048 (0x0800)

IP Header:
Version: 4
IHL: 5
DSCP/ECN: 0x00/0x00
Total Length: 60
Identification: 12345
Flags/Offset: 0x00/0x00
TTL: 64
Protocol: 6
Header Checksum: 0x1234
Source IP: 192.168.1.100
Destination IP: 8.8.8.8

TCP Header:
Source Port: 50000
Destination Port: 53
Sequence Number: 1234567890
Ack Number: 0
Data Offset/Flags: 0x5010
Window Size: 65535
Checksum: 0xabcd
Urgent Pointer: 0
IGNORE_WHEN_COPYING_START
content_copy
download
Use code with caution.
IGNORE_WHEN_COPYING_END

## Disclaimer

This tool is provided for educational purposes only. Use it responsibly and ethically, and only on networks you are authorized to monitor. The author is not responsible for any misuse of this tool.

## Acknowledgements

I would like to thank CodeAlpha for providing me with this valuable internship opportunity and for their guidance throughout this project. I also thank [mention any specific mentors or colleagues who helped you].

## Contact
