import socket
import struct
import sys
import textwrap

TAB_1 = '\t '
TAB_2 = '\t\t '
TAB_3 = '\t\t\t '
TAB_4 = '\t\t\t\t '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    try:
        if sys.platform.startswith('win'):
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind(('0.0.0.0', 0))
            if hasattr(socket, 'SIO_RCVALL'):
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print('Windows mode: capturing IPv4 packets at the IP layer.')
            print('Run this as Administrator for packet capture to work.')
            socket_family = 'win'
        else:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            socket_family = 'linux'
    except AttributeError:
        print('Raw sockets are not available on this system.')
        return
    except OSError as exc:
        print(f'Could not create raw socket: {exc}')
        print('Run with the required permissions (root/admin).')
        return

    while True:
        raw_data, addr = conn.recvfrom(65536)

        if socket_family == 'win':
            version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
            print('\nIPv4 Packet:')
            print(TAB_1 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_1 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
            continue

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# return properly formatted MAC address
def get_mac_addr(bytes_addr):
    return ':'.join('{:02x}'.format(byte) for byte in bytes_addr).upper()


# unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(str(part) for part in addr)


# unpack ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]


# unpack TCP Segment
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHIIH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# unpack UDP Segment
def udp_segment(data):
    src_port, dest_port, size, checksum = struct.unpack('!HHHH', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))


if __name__ == '__main__':
    main()