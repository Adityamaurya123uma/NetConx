import socket
import struct
import textwrap

buffer = []
MAX_BUFFER_SIZE = 100

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
            print(f"Captured frame length: {len(data)}, Protocol: {eth_proto}")

            # Process only IPv4 packets
            if eth_proto == 8:
                if len(data) < 20:
                    print('\tInsufficient data for IPv4 packet. Skipping...')
                    continue  # Skip to the next packet

                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print('\tIPv4 Packet:')
                print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print('\t\tProtocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                # ICMP, TCP, UDP, or other protocols
                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('\tICMP Packet:')
                    print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(format_multi_line('\t\t\t', data))

                elif proto == 6:  # TCP
                    tcp_segment_data = tcp_segment(data)
                    print('\tTCP Segment:')
                    print('\t\tSource Port: {}, Destination Port: {}'.format(tcp_segment_data[0], tcp_segment_data[1]))
                    print(format_multi_line('\t\t\t', tcp_segment_data[-1]))

                elif proto == 17:  # UDP
                    src_port, dest_port, length, data = udp_segment(data)
                    print('\tUDP Segment:')
                    print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

                else:
                    print('\tOther Data:')
                    print(format_multi_line('\t\t', data))
            else:
                print('\tNon-IPv4 frame detected. Skipping...')
        except Exception as e:
            print('Error:', e)


#Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (i.e. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    if len(data) < 20:
        raise ValueError("Insufficient data for IPv4 header. Expected 20 bytes, got {}".format(len(data)))
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# format multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)  # Reduce size by the prefix length
    if isinstance(string, bytes):  # Check if the input is bytes
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)  # Convert bytes to a string
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()
