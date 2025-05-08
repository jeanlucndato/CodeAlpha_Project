import socket
import struct
import sys
from collections import namedtuple

def analyze_icmp_header(packet):
    """
    Analyzes an ICMP header.

    Args:
        packet (bytes): The ICMP packet data (starting after the IP header).

    Returns:
        namedtuple: A named tuple containing the ICMP header fields, or None on error.
    """
    ICMPHeader = namedtuple('ICMPHeader', ['type', 'code', 'checksum', 'rest_of_header'])

    if len(packet) < 4:
        print("ICMP packet too short to analyze header.")
        return None

    try:
        icmp_type, icmp_code, icmp_checksum, rest_of_header = struct.unpack('!BBH4s', packet[:8])
        return ICMPHeader(icmp_type, icmp_code, icmp_checksum, rest_of_header)
    except struct.error as e:
        print(f"Error unpacking ICMP header: {e}")
        return None

def analyze_udp_header(packet):
    """
    Analyzes a UDP header.

    Args:
        packet (bytes): The UDP packet data (starting after the IP header).

    Returns:
        namedtuple: A named tuple containing the UDP header fields, or None on error.
    """
    UDPHeader = namedtuple('UDPHeader', ['src_port', 'dest_port', 'length', 'checksum'])
    if len(packet) < 8:
        print("UDP packet too short to analyze header.")
        return None
    try:
        udp_header = struct.unpack('!HHHH', packet[:8])
        return UDPHeader(*udp_header)
    except struct.error as e:
        print(f"Error unpacking UDP header: {e}")
        return None


def analyze_tcp_header(packet):
    """
    Analyzes a TCP header.

    Args:
        packet (bytes): The TCP packet data (starting after the IP header).

    Returns:
        namedtuple: A named tuple containing the TCP header fields, or None on error.
    """
    TCPHeader = namedtuple('TCPHeader', [
        'src_port', 'dest_port', 'seq_number', 'ack_number', 'data_offset_reserved_flags',
        'window_size', 'checksum', 'urgent_pointer'
    ])

    if len(packet) < 20:
        print("TCP packet too short to analyze header.")
        return None

    try:
        tcp_header = struct.unpack('!HHLLHHHH', packet[:20])
        return TCPHeader(*tcp_header)
    except struct.error as e:
        print(f"Error unpacking TCP header: {e}")
        return None



def analyze_ip_header(packet):
    """
    Analyzes an IP header.

    Args:
        packet (bytes): The IP packet data (starting from the beginning of the IP header).

    Returns:
        namedtuple: A named tuple containing the IP header fields, or None on error.
    """
    IPHeader = namedtuple('IPHeader', [
        'version', 'ihl', 'dscp', 'ecn', 'total_length', 'identification',
        'flags_fragment_offset', 'ttl', 'protocol', 'header_checksum',
        'src_ip', 'dest_ip'
    ])
    if len(packet) < 20:
        print("IP packet too short to analyze header.")
        return None

    try:
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        dscp_ecn = ip_header[1]
        total_length = ip_header[2]
        identification = ip_header[3]
        flags_fragment_offset = ip_header[4]
        ttl = ip_header[5]
        protocol = ip_header[6]
        header_checksum = ip_header[7]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        return IPHeader(version, ihl, dscp_ecn, total_length, identification,
                          flags_fragment_offset, ttl, protocol, header_checksum,
                          src_ip, dest_ip)
    except struct.error as e:
        print(f"Error unpacking IP header: {e}")
        return None
    except Exception as e:
        print(f"Error converting IP addresses: {e}")
        return None



def analyze_ethernet_header(packet):
    """
    Analyzes an Ethernet header.

    Args:
        packet (bytes): The Ethernet frame data.

    Returns:
        namedtuple: A named tuple containing the Ethernet header fields, or None on error.
    """
    EthernetHeader = namedtuple('EthernetHeader', ['dest_mac', 'src_mac', 'protocol_type'])
    if len(packet) < 14:
        print("Ethernet frame too short to analyze header.")
        return None
    try:
        eth_header = struct.unpack('!6s6sH', packet[:14])
        dest_mac = ":".join(f"{b:02x}" for b in eth_header[0])
        src_mac = ":".join(f"{b:02x}" for b in eth_header[1])
        protocol_type = eth_header[2]
        return EthernetHeader(dest_mac, src_mac, protocol_type)
    except struct.error as e:
        print(f"Error unpacking Ethernet header: {e}")
        return None



def sniff_and_analyze_packets(interface=None):
    """
    Sniffs network packets and analyzes their headers.

    Args:
        interface (str, optional): The network interface to sniff on. If None,
            the function will try to sniff on all interfaces.  Defaults to None.
    """
    # Create a raw socket.
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        if interface:
            s.bind((interface, 0))  # Bind to a specific interface
    except socket.error as msg:
        print(f"Socket could not be created or bound. Error: {msg}")
        sys.exit()

    print(f"Sniffing packets on interface: {interface if interface else 'all interfaces'}...")

    try:
        while True:
            # Receive a packet
            packet, _ = s.recvfrom(65535)

            # Analyze Ethernet Header
            eth_header = analyze_ethernet_header(packet[:14])
            if not eth_header:
                continue  # Skip to the next packet

            print("\nEthernet Header:")
            print(f"  Destination MAC: {eth_header.dest_mac}")
            print(f"  Source MAC:      {eth_header.src_mac}")
            print(f"  Protocol Type:   {eth_header.protocol_type} (0x{eth_header.protocol_type:04x})")

            # Handle IP packets (0x0800)
            if eth_header.protocol_type == 2048:
                ip_header = analyze_ip_header(packet[14:])
                if not ip_header:
                    continue

                print("  IP Header:")
                print(f"    Version:          {ip_header.version}")
                print(f"    IHL:              {ip_header.ihl}")
                print(f"    DSCP/ECN:         {ip_header.dscp:02x}/{ip_header.ecn:02x}")
                print(f"    Total Length:     {ip_header.total_length}")
                print(f"    Identification:   {ip_header.identification:04x}")
                print(f"    Flags/Offset:     {ip_header.flags_fragment_offset:04x}")
                print(f"    TTL:              {ip_header.ttl}")
                print(f"    Protocol:         {ip_header.protocol}")
                print(f"    Header Checksum:  {ip_header.header_checksum:04x}")
                print(f"    Source IP:        {ip_header.src_ip}")
                print(f"    Destination IP:   {ip_header.dest_ip}")

                # Handle TCP packets (6)
                if ip_header.protocol == 6:
                    tcp_header = analyze_tcp_header(packet[14 + (ip_header.ihl * 4):])
                    if tcp_header:
                        print("    TCP Header:")
                        print(f"      Source Port:      {tcp_header.src_port}")
                        print(f"      Destination Port: {tcp_header.dest_port}")
                        print(f"      Sequence Number:  {tcp_header.seq_number}")
                        print(f"      Ack Number:       {tcp_header.ack_number}")
                        print(f"      Data Offset/Flags: 0x{tcp_header.data_offset_reserved_flags:04x}")
                        print(f"      Window Size:      {tcp_header.window_size}")
                        print(f"      Checksum:         {tcp_header.checksum:04x}")
                        print(f"      Urgent Pointer:   {tcp_header.urgent_pointer}")
                    else:
                        print("    Error: Could not analyze TCP header")

                # Handle UDP packets (17)
                elif ip_header.protocol == 17:
                    udp_header = analyze_udp_header(packet[14 + (ip_header.ihl * 4):])
                    if udp_header:
                        print("    UDP Header:")
                        print(f"      Source Port:      {udp_header.src_port}")
                        print(f"      Destination Port: {udp_header.dest_port}")
                        print(f"      Length:           {udp_header.length}")
                        print(f"      Checksum:         {udp_header.checksum:04x}")
                    else:
                        print("    Error: Could not analyze UDP header")
                # Handle ICMP packets (1)
                elif ip_header.protocol == 1:
                    icmp_header = analyze_icmp_header(packet[14 + (ip_header.ihl * 4):])
                    if icmp_header:
                        print("    ICMP Header:")
                        print(f"      Type:             {icmp_header.type}")
                        print(f"      Code:             {icmp_header.code}")
                        print(f"      Checksum:         {icmp_header.checksum:04x}")
                        print(f"      Rest of Header:   {icmp_header.rest_of_header}")
                    else:
                        print("   Error: Could not analyze ICMP header")

                else:
                    print("    Protocol:         Other (Not TCP, UDP, or ICMP)")

            else:
                print("  Protocol Type:   Other (Not IP)")

    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        s.close()  # Ensure the socket is closed

if __name__ == "__main__":
    # Get the interface name from the command line, if provided
    if len(sys.argv) > 1:
        interface_name = sys.argv[1]
        sniff_and_analyze_packets(interface_name)
    else:
        sniff_and_analyze_packets()  # Sniff on all interfaces
