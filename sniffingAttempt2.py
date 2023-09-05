import socket
import struct
import textwrap

HOST = socket.gethostbyname(socket.gethostname())

tab = lambda num: "\t"*num
def main():
    ip = socket.gethostbyname(socket.gethostname())
    port = 0

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #conn.bind((ip, port))
    #conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data , addr = conn.recvfrom(65536)
        #print("Here")
        #print(raw_data[:28])
        dst_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nMAC Information: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dst_mac, src_mac, eth_proto))
        
        #eth_proto == 8 for IPv4
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        print(tab(1) + 'IPv4 Packet:')
        print(tab(2) + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        print(tab(2) + 'Protocol: {}, Source Address: {}, Destination: {}'.format(proto, src, target))
        
        #ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print(tab(1) + 'ICMP Packet:')
            print(tab(2) + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
            
        #TCP
        elif proto == 6:
            (src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
            print(tab(1) + 'TCP Segment')
            print(tab(2) + 'Src Port: {}, Dest Port: {}, '.format(src_port,dest_port))
            print(tab(2) + 'Sequence: {}, Acknowledgement: {},'.format(sequence, ack))
            print(tab(2) + 'Flags: ')
            print(tab(2) + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
        
	#UDP
        elif proto == 17:
            src_port, dest_port, size, data = udp_segment(data);
            print(tab(1) + 'UDP Packet: ')
            print(tab(2) + 'Src Port: {}, Dest Port: {}, Length: {}'.format(src_port, dest_port, size))
        



# Unpack ethernet frame
def ethernet_frame(data):
    dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]
# Return properly formatted MAC address (like AA:BB:....:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr
def get_protocol(bytes_proto):
    bytes_str = map('{:02x}'.format, bytes_proto)
    protocol = ''.join(bytes_str).upper()
    return protocol
    


#Unpack Ipv4 header
def ipv4_packet(data):
    ver_head_len = data[0]
    version = ver_head_len >> 4
    header_length = (ver_head_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]
#Return formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))
    
    
#Unpack ICMP header
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4: ]
    
#Unpack TCP header
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
#Unpack UDP header
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
    
    
main()
