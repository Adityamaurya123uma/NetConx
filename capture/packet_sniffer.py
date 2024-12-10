import socket
import struct
import textwrap
import time

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    buffer = []
    MAX_BUFFER_SIZE = 100
    BUFFER_TIMEOUT = 2
    last_flush_time = time.time()

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            buffer.append(raw_data)

            current_time = time.time()
            if len(buffer) >= MAX_BUFFER_SIZE or (current_time - last_flush_time) > BUFFER_TIMEOUT:
                process_buffer(buffer)
                buffer.clear()
                last_flush_time = current_time
        except Exception as e:
            print("Error:", e)


def process_buffer(buffer):
    for raw_data in buffer:
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        if eth_proto == 8:  # IPv4
            process_ipv4_packet(data)
        if eth_proto == 0x86DD: # IPv6
            process_ipv6_packet(data)


#Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (i.e. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

###########################################################
# IPv4
###########################################################

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

def process_ipv4_packet(data):
    try:
        version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
        print('\tIPv4 Packet:')
        print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        print('\t\tProtocol: {}, Source: {}, Target: {}'.format(proto, src, target))

        if proto == 1:  # ICMP
            process_icmp_packet(data)
        elif proto == 6:  # TCP
            process_tcp_segment(data)
        elif proto == 17:  # UDP
            process_udp_segment(data)
        else:
            print('\t\tOther Protocol Data:')
            print(format_multi_line('\t\t\t', data))
    except ValueError as e:
        print('\tError processing IPv4 packet:', e)

def process_icmp_packet(data):
    icmp_type, code, checksum, data = icmp_packet(data)
    print('\tICMP Packet:')
    print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
    print(format_multi_line('\t\t\t', data))

def process_udp_segment(data):
    src_port, dest_port, length, data = udp_segment(data)
    print(f'\tUDP Segment: Source Port: {src_port}, Destination Port: {dest_port}')
    if src_port == 53 or dest_port == 53:
        print("\tDNS Detected:")
        process_dns(data)
    else:
        print(format_multi_line('\t\t', data))


def process_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags, data = tcp_segment(data)
    print(f'\tTCP Segment: Source Port: {src_port}, Destination Port: {dest_port}')
    if src_port == 80 or dest_port == 80:
        print("\tHTTP Detected:")
        process_http(data)
    elif src_port == 443 or dest_port == 443:
        print("\tTLS/HTTPS traffic detected. (Decryption requires additional setup)")
    else:
        print(format_multi_line('\t\t', data))



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

###########################################################
# IPv6
###########################################################

# Unpack IPv6 packet
def ipv6_packet(data):
    version_traffic_flow = struct.unpack('! I', data[:4])[0]
    version = (version_traffic_flow >> 28) & 0xF
    payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
    src_addr = ipv6(data[8:24])
    dest_addr = ipv6(data[24:40])
    return version, payload_length, next_header, hop_limit, src_addr, dest_addr, data[40:]

# Return formatted IPv6 addresses
def ipv6(addr):
    return ':'.join(f"{addr[i]:02x}{addr[i+1]:02x}" for i in range(0, len(addr), 2))

def process_ipv6_packet(data):
    try:
        version, payload_length, next_header, hop_limit, src_addr, dest_addr, payload = ipv6_packet(data)
        print(f"\tIPv6 Packet:")
        print('\t\tVersion: {}, Payload Length: {}, Next Header: {}, Hop Limit: {}'.format(
            version, payload_length, next_header, hop_limit
        ))
        print('\t\tSource: {}, Destination: {}'.format(src_addr, dest_addr))

        # Route to upper-layer protocol handlers based on Next Header
        if next_header == 58:  # ICMPv6
            process_icmp_packet(payload)
        elif next_header == 6:  # TCP
            process_tcp_segment(payload)
        elif next_header == 17:  # UDP
            process_udp_segment(payload)
        else:
            print('\t\tOther Protocol Data:')
            print(format_multi_line('\t\t\t', payload))
    except ValueError as e:
        print('\tError processing IPv6 packet:', e)

def process_http(data):
    try:
        http_data = data.decode('utf-8', errors='ignore')
        headers = http_data.split('\r\n')
        for header in headers:
            print(f"\tHTTP: {header}")
    except Exception as e:
        print(f"\tError parsing HTTP data: {e}")


def process_dns(data):
    try:
        transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('! H H H H H H', data[:12])
        print(f"\tDNS: Transaction ID: {transaction_id}, Questions: {questions}")
        # Implement deeper decoding for queries/answers if needed.
    except Exception as e:
        print(f"\tError parsing DNS data: {e}")


main()
