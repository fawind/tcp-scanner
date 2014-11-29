#!/usr/bin/env python

# Portscanner for SYN- and CONNECT-Scans using raw sockets and pcap
# supports rudimentary OS-detection
#
# runs on:
#       Linux
#       Python 2.7.8
# requires:
#       pcap

import sys
import time
import random
import re
import thread
import subprocess
import socket
import pcap
from sets import Set
from struct import *


# global variables
src_ip = ''
dest_ip = ''
device = ''
open_ports = Set([])
running = False

windows = 0
linux = 0
mac = 0


def main(argv = None):

    params = validate_params(argv)
    method = params[0]
    ports = params[1]

    # set the source ip and the name of the network device
    set_host_info()

    print 'Starting ' + method + '-scan on ' + dest_ip + ' using the device ' + device + '.\n'

    if method == 'CONNECT':
        scan_connect(ports)
    if method == 'SYN':
        scan_syn(ports)

    print_results()


# ==================== Validation ====================

def valid_ip(ip):
    IP_RE = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return IP_RE.match(ip)
def valid_scan(scan):
    return scan == 'CONNECT' or scan == 'SYN'

# validates the program parameters
# sets the target ip and returns the validated scan_method and port range
def validate_params(argv):
    error = False
    scan = ''
    port_range = []
    default_range = [(15, 30)]

    # validate IP and scan method
    if len(argv) > 3 and len(argv) <= 4:
        ip = argv[1]
        scan = argv[2]

        if valid_ip(ip) and valid_scan(scan):
            global dest_ip
            dest_ip = ip
        else:
            error = True
    else:
        error = True

    # validate ports
    if len(argv) == 4:
        str_ports = argv[3]

        # range scan
        if str_ports.find('-') != -1:
            min_port, max_port = str_ports.split('-')

            if min_port.isdigit() and max_port.isdigit() and min_port <= max_port:
                port_range = [(int(min_port), int(max_port)+1)]
            else:
                error = True

        # single ports scan
        elif str_ports.find(',') != -1:
            ports_split = str_ports.split(',')

            for port in ports_split:
                if port.isdigit():
                    # single ports are stored as a portrange from port to port+1
                    port_range.append((int(port), int(port)+1))
                else:
                    error = True
                    break
        else:
            error = True

    # no ports specified
    else:
        port_range = default_range

    if not error:
        return (scan, port_range)
    else:
        print "Invalid options"
        print "Usage: python scanner.py IP CONNECT|SYN [PORTS]"
        sys.exit()

def set_host_info():
    global device
    device = pcap.lookupdev()

    """
    Since socket.gethostbyname(socket.gethostname()) returns 127.0.0.1
    we have to find another way of getting our own ip

        a) parse form the command 'ip addr'
                or
        b) connect to a server and retrieve it using getsocketname()
    """

    """
    # runs the shell-cmd 'ip addr' to retrieve the ip
    p = subprocess.Popen(['ip', 'addr'], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    output, errors = p.communicate()

    # regex to match the ip of the host
    IP_RE = re.compile(r"(?<="+device+":)(?:.*inet\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.DOTALL)

    # retrieve and set the ip of the host
    match_ip = re.search(IP_RE, output)
    if match_ip:
        global src_ip
        src_ip = match_ip.group(1)
    else:
        print "Error parsing the host ip form 'ip addr'"
        sys.exit()
    """

    # connect to a server and retrieve your own ip
    global src_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    src_ip = s.getsockname()[0]


# ==================== Scan Methods ====================

def scan_connect(ports):
    for port_range in ports:
        for port in range(port_range[0], port_range[1]):
            s = create_socket('CONNECT')
            try:
                s.connect((dest_ip, port))
                open_ports.add(port)
                s.close()
            except:
                s.close()

def scan_syn(ports):
    global running
    running = True

    s = create_socket('SYN')

    # start a new thread to catch the returning packets
    thread.start_new(catch_packets, ())
    time.sleep(0.5)

    # create and send out the packets
    for port_range in ports:
        for port in range(port_range[0], port_range[1]):
            packet = create_tcp_header(port)

            # send packet to target host
            s.sendto(packet, (dest_ip, 0))

    # final wait to catch the last packets
    time.sleep(5)
    running = False
    s.close()


# ==================== Packet Creation ====================

def create_socket(scan_type):
    s = None

    try:
        if scan_type == 'SYN':
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
    except socket.error:
        print "Error creating socket. Did you run the program as root?"
        sys.exit()

    return s

# calculate the checksum of a packet
# src: http://www.binarytides.com/raw-socket-programming-in-python-linux
def calc_checksum(packet):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(packet), 2):
        w = ord(packet[i]) + (ord(packet[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def create_tcp_header(dest_port):
    # tcp header fields
    src_port = random.randint(40000, 65535)
    dest_port = dest_port
    seq_nr = 454
    ack_nr = 0
    offset = 5

    # flags
    urg = 0
    ack = 0
    psh = 0
    rst = 0
    syn = 1
    fin = 0

    window = socket.htons(5840)
    checksum = 0
    urg_pointer = 0

    packet_offset = (offset << 4) | 0
    flags = fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4) | (urg << 5)

    # build a pseudo header to calculate the checksum
    tcp_header = pack('!HHLLBBHHH', src_port, dest_port, seq_nr, ack_nr, packet_offset,
                      flags,  window, checksum, urg_pointer)

    psh_source = socket.inet_aton(src_ip)
    psh_dest = socket.inet_aton(dest_ip)
    psh_placeholder = 0
    psh_protocol = socket.IPPROTO_TCP
    psh_tcp_length = len(tcp_header)

    # build the pseudo packet
    psh = pack('!4s4sBBH', psh_source, psh_dest, psh_placeholder, psh_protocol, psh_tcp_length)
    psh = psh + tcp_header

    # calculate the checksum
    checksum = calc_checksum(psh)

    # build the packet with the correct checksum
    tcp_header = pack("!HHLLBBH", src_port, dest_port, seq_nr, ack_nr, packet_offset, flags, window)\
                 + pack('H', checksum) + pack('!H', urg_pointer)

    return tcp_header


# ================= Handlers for Incoming Packets =================

# runs in a thread and catches all packets using pcap
def catch_packets():
    p = pcap.pcapObject()
    p.open_live(device, 1600, 0, 100)

    # get only packets from the target
    p.setfilter('src host {0}'.format(dest_ip), 0, 0)

    try:
        while running:
            p.dispatch(1, check_ack)
    except KeyboardInterrupt:
        print str(sys.exc_type)

# checks if the syn|ack-flags are set
def check_ack(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14] == '\x08\x00':
        parsed_data = parse_packet(data[14:])

        # check if the packet src is the target and if the syn|ack-flags are set
        if parsed_data[0] == dest_ip and parsed_data[1] == 1 and parsed_data[2] == 1:
            # save the open port and send the packet to the os detection
            open_ports.add(parsed_data[3])
            guess_os(data[14:])

# returns all relevant information from a packet
def parse_packet(packet):
    data = ['src_ip', 'syn-flag', 'ack-flag', 'port']

    header_length = ord(packet[0]) & 0x0f

    # src ip
    data[0] = pcap.ntoa(unpack('i', packet[12:16])[0])
    # syn-flag
    data[1] = ord(packet[4 * header_length + 13]) >> 1 & 0x1
    # ack-flag
    data[2] = ord(packet[4 * header_length + 13]) >> 4 & 0x1
    # port number
    data[3] = (ord(packet[4 * header_length]) << 8) + ord(packet[4 * header_length + 1])

    return data

# increases the os-counter if a os-specific characteristic is found
def guess_os(packet):
    header_length = ord(packet[0]) & 0x0f

    ttl = ord(packet[8])
    do_not_fragment = (ord(packet[6]) & 0xe0) >> 6 & 0x1
    window_size = (ord(packet[4 * header_length + 14]) << 8) + ord(packet[4 * header_length + 15])

    global windows
    global linux
    global mac

    if ttl < 128:
        linux += 1
    elif ttl >= 128 and ttl < 255:
        windows += 1
    else:
        mac += 1

    if do_not_fragment == 1:
        windows += 1
        linux += 1
    else:
        mac += 1

    if window_size < 500:
        mac += 1
    elif window_size >= 5000 and window_size < 65000:
        linux += 1
    else:
        windows += 1


# ==================== Format Output ====================

def print_results():
    if open_ports is not None:
        ports_sorted = sorted(open_ports)

        print "PORT    STATE    SERVICE"

        for port in ports_sorted:
            intend = " " * (8 - len(str(port)))

            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            print str(port) + intend + "open" + (" "*5) + service

        max_counter = max(windows, linux, mac)
        if [windows, linux, mac].count(max_counter) != 1:
            print "\nNot enough data to guess the os"
        else:
            if max_counter == windows:
                print "\nThe OS might be Windows"
            if max_counter == linux:
                print "\nThe OS might be Linux"
            if max_counter == mac:
                print "\nThe OS might be iOS/MAC"

    else:
        print "No open ports found"


if __name__ == "__main__":
    main(sys.argv)
