import os
import sys
import ctypes
import socket, struct

CONN_DEVICE_FILE_PATH =     "/sys/class/fw/conns/conns_mitm"

so_file = os.getcwd() + "/functions.so"
functions = ctypes.CDLL(so_file)

#
# Returns the man in the middle port from the kernel-space
#
def get_mitm_port(src_ip, src_port, dst_ip, dst_port):
    if os.path.exists(CONN_DEVICE_FILE_PATH):
        return functions.get_mitm_port(ip2long(src_ip), src_port, ip2long(dst_ip), dst_port)
    else:
        sys.exit("Error: can't find the device file")

#
# Calls to set the man in the middle port to the kernel-space
#
def set_mitm_port(src_ip, src_port, dst_ip, dst_port, mitm_port):
    if os.path.exists(CONN_DEVICE_FILE_PATH):
        return functions.set_mitm_port(ip2long(src_ip), src_port, ip2long(dst_ip), dst_port, mitm_port)
    else:
        sys.exit("Error: can't find the device file")
        
#
# Calls the kernel-space to create ftp-data connections
#
def create_ftp_entries(ftp_data_port):
    if os.path.exists(CONN_DEVICE_FILE_PATH):
        return functions.create_ftp_entries(ip2long("10.1.2.2"), "20", ip2long("10.1.1.1"), ftp_data_port)
    else:
        sys.exit("Error: can't find the device file")


#
# Converts string ip (4 dotted decimal numbers) to little endian number
#
def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]