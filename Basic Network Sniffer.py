#!/usr/bin/env python3  # Shebang to specify Python 3 interpreter
"""
Network Packet Sniffer  # Docstring: Title of the tool
Educational tool for network analysis and troubleshooting  # Docstring: Purpose of the tool
Note: Requires root/administrator privileges to capture packets  # Docstring: Warning about privileges
"""

import socket  # Import socket module for network operations
import struct  # Import struct for byte packing/unpacking
import textwrap  # Import textwrap for formatting output
import sys  # Import sys for system-specific parameters and functions
import time  # Import time for time-related functions (not used)
from datetime import datetime  # Import datetime for timestamping

class PacketSniffer:  # Define PacketSniffer class
    def __init__(self, interface=None):  # Constructor with optional interface argument
        self.interface = interface  # Store network interface (not used in code)
        self.packet_count = 0  # Initialize packet counter
        
    def create_socket(self):  # Method to create a raw socket
        """Create raw socket for packet capture"""  # Docstring
        try:
            # Create raw socket
            if sys.platform.startswith('win'):  # Check if running on Windows
                # Windows
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # Create raw socket for IP
                s.bind((socket.gethostbyname(socket.gethostname()), 0))  # Bind to local IP
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode
            else:
                # Linux/Unix
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  # Create raw socket for all protocols
            return s  # Return the created socket
        except PermissionError:  # Handle lack of privileges
            print("Error: Root/Administrator privileges required!")  # Print error message
            sys.exit(1)  # Exit program
        except Exception as e:  # Handle other exceptions
            print(f"Error creating socket: {e}")  # Print error message
            sys.exit(1)  # Exit program

    def parse_ethernet_header(self, data):  # Parse Ethernet header from packet data
        """Parse Ethernet header"""  # Docstring
        eth_header = struct.unpack('!6s6sH', data[:14])  # Unpack Ethernet header (dest MAC, src MAC, type)
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])  # Format destination MAC address
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])  # Format source MAC address
        eth_type = socket.ntohs(eth_header[2])  # Get Ethernet type (convert to host byte order)
        return dest_mac, src_mac, eth_type, data[14:]  # Return MACs, type, and remaining data

    def parse_ip_header(self, data):  # Parse IP header from packet data
        """Parse IP header"""  # Docstring
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])  # Unpack IP header fields
        
        version = ip_header[0] >> 4  # Extract IP version
        header_length = (ip_header[0] & 0xF) * 4  # Calculate header length in bytes
        ttl = ip_header[5]  # Time to live
        protocol = ip_header[6]  # Protocol number
        src_ip = socket.inet_ntoa(ip_header[8])  # Source IP address
        dest_ip = socket.inet_ntoa(ip_header[9])  # Destination IP address
        
        return {  # Return parsed IP header fields and remaining data
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'data': data[header_length:]
        }

    def parse_tcp_header(self, data):  # Parse TCP header from packet data
        """Parse TCP header"""  # Docstring
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])  # Unpack TCP header fields
        
        src_port = tcp_header[0]  # Source port
        dest_port = tcp_header[1]  # Destination port
        seq_num = tcp_header[2]  # Sequence number
        ack_num = tcp_header[3]  # Acknowledgment number
        flags = tcp_header[5]  # TCP flags byte
        
        # TCP flags
        flag_urg = (flags & 32) >> 5  # URG flag
        flag_ack = (flags & 16) >> 4  # ACK flag
        flag_psh = (flags & 8) >> 3  # PSH flag
        flag_rst = (flags & 4) >> 2  # RST flag
        flag_syn = (flags & 2) >> 1  # SYN flag
        flag_fin = flags & 1  # FIN flag
        
        header_length = (tcp_header[4] >> 4) * 4  # TCP header length in bytes
        
        return {  # Return parsed TCP header fields and remaining data
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'data': data[header_length:]
        }

    def parse_udp_header(self, data):  # Parse UDP header from packet data
        """Parse UDP header"""  # Docstring
        udp_header = struct.unpack('!HHHH', data[:8])  # Unpack UDP header fields
        
        return {  # Return parsed UDP header fields and remaining data
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3],
            'data': data[8:]
        }

    def format_data(self, data, size=16):  # Format raw data for display
        """Format raw data for display"""  # Docstring
        if not data:  # If data is empty
            return ""  # Return empty string
        
        result = []  # Initialize result list
        for i in range(0, len(data), size):  # Iterate over data in chunks
            chunk = data[i:i+size]  # Get chunk of data
            hex_part = ' '.join(f'{b:02x}' for b in chunk)  # Format as hex
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)  # Format as ASCII
            result.append(f'{hex_part:<{size*3}} {ascii_part}')  # Append formatted line
        
        return '\n'.join(result)  # Join lines and return

    def get_protocol_name(self, protocol_num):  # Get protocol name from number
        """Get protocol name from number"""  # Docstring
        protocols = {  # Dictionary of protocol numbers to names
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')  # Return protocol name or unknown

    def print_packet_info(self, packet_data):  # Print formatted packet information
        """Print formatted packet information"""  # Docstring
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # Get current timestamp
        
        print(f"\n{'='*60}")  # Print separator
        print(f"Packet #{self.packet_count} - {timestamp}")  # Print packet number and timestamp
        print(f"{'='*60}")  # Print separator
        
        # Parse Ethernet (if not Windows)
        if not sys.platform.startswith('win'):  # If not running on Windows
            try:
                dest_mac, src_mac, eth_type, ip_data = self.parse_ethernet_header(packet_data)  # Parse Ethernet header
                print(f"Ethernet Header:")  # Print Ethernet header label
                print(f"  Source MAC: {src_mac}")  # Print source MAC
                print(f"  Dest MAC: {dest_mac}")  # Print destination MAC
                print(f"  Type: 0x{eth_type:04x}")  # Print Ethernet type
                
                if eth_type == 0x0800:  # IPv4
                    packet_data = ip_data  # Update packet data to IP payload
            except:
                pass  # Ignore errors
        
        # Parse IP header
        try:
            ip_info = self.parse_ip_header(packet_data)  # Parse IP header
            protocol_name = self.get_protocol_name(ip_info['protocol'])  # Get protocol name
            
            print(f"\nIP Header:")  # Print IP header label
            print(f"  Version: {ip_info['version']}")  # Print IP version
            print(f"  Header Length: {ip_info['header_length']} bytes")  # Print header length
            print(f"  TTL: {ip_info['ttl']}")  # Print TTL
            print(f"  Protocol: {protocol_name}")  # Print protocol name
            print(f"  Source IP: {ip_info['src_ip']}")  # Print source IP
            print(f"  Destination IP: {ip_info['dest_ip']}")  # Print destination IP
            
            # Parse transport layer
            if ip_info['protocol'] == 6:  # TCP
                tcp_info = self.parse_tcp_header(ip_info['data'])  # Parse TCP header
                active_flags = [flag for flag, value in tcp_info['flags'].items() if value]  # Get active TCP flags
                
                print(f"\nTCP Header:")  # Print TCP header label
                print(f"  Source Port: {tcp_info['src_port']}")  # Print source port
                print(f"  Dest Port: {tcp_info['dest_port']}")  # Print destination port
                print(f"  Sequence: {tcp_info['seq_num']}")  # Print sequence number
                print(f"  Acknowledgment: {tcp_info['ack_num']}")  # Print acknowledgment number
                print(f"  Flags: {', '.join(active_flags) if active_flags else 'None'}")  # Print TCP flags
                
                if tcp_info['data']:  # If TCP payload exists
                    print(f"\nTCP Data ({len(tcp_info['data'])} bytes):")  # Print TCP data length
                    print(textwrap.indent(self.format_data(tcp_info['data'][:64]), '  '))  # Print formatted TCP data
                    
            elif ip_info['protocol'] == 17:  # UDP
                udp_info = self.parse_udp_header(ip_info['data'])  # Parse UDP header
                
                print(f"\nUDP Header:")  # Print UDP header label
                print(f"  Source Port: {udp_info['src_port']}")  # Print source port
                print(f"  Dest Port: {udp_info['dest_port']}")  # Print destination port
                print(f"  Length: {udp_info['length']}")  # Print UDP length
                
                if udp_info['data']:  # If UDP payload exists
                    print(f"\nUDP Data ({len(udp_info['data'])} bytes):")  # Print UDP data length
                    print(textwrap.indent(self.format_data(udp_info['data'][:64]), '  '))  # Print formatted UDP data
                    
        except Exception as e:  # Handle parsing errors
            print(f"Error parsing packet: {e}")  # Print error message
            print(f"Raw data ({len(packet_data)} bytes):")  # Print raw data length
            print(textwrap.indent(self.format_data(packet_data[:64]), '  '))  # Print formatted raw data

    def start_sniffing(self, count=0):  # Start packet capture
        """Start packet capture"""  # Docstring
        print("Starting packet capture...")  # Print start message
        print("Note: This captures packets on your network interface")  # Print note
        print("Press Ctrl+C to stop\n")  # Print stop instruction
        
        sock = self.create_socket()  # Create raw socket
        
        try:
            while True:  # Infinite loop to capture packets
                if count > 0 and self.packet_count >= count:  # If capture limit reached
                    break  # Exit loop
                    
                data, addr = sock.recvfrom(65536)  # Receive packet data
                self.packet_count += 1  # Increment packet counter
                self.print_packet_info(data)  # Print packet information
                
        except KeyboardInterrupt:  # Handle Ctrl+C
            print(f"\n\nCapture stopped. Total packets captured: {self.packet_count}")  # Print stop message
        except Exception as e:  # Handle other errors
            print(f"Error during capture: {e}")  # Print error message
        finally:
            sock.close()  # Close socket

def main():  # Main function
    print("Network Packet Sniffer")  # Print tool name
    print("=====================")  # Print separator
    print("WARNING: This tool requires root/administrator privileges")  # Print warning
    print("Use only on networks you own or have permission to monitor")  # Print usage warning
    print()  # Print empty line
    
    try:
        # Get capture count
        count_input = input("Enter number of packets to capture (0 for unlimited): ")  # Prompt user for packet count
        count = int(count_input) if count_input.strip() else 0  # Convert input to integer
        
        sniffer = PacketSniffer()  # Create PacketSniffer instance
        sniffer.start_sniffing(count)  # Start sniffing with specified count
        
    except ValueError:  # Handle invalid input
        print("Invalid input. Using unlimited capture.")  # Print error message
        sniffer = PacketSniffer()  # Create PacketSniffer instance
        sniffer.start_sniffing()  # Start sniffing with unlimited count
    except Exception as e:  # Handle other errors
        print(f"Error: {e}")  # Print error message

if __name__ == "__main__":  # If script is run directly
    main()  # Call main function