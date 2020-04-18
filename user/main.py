import sys
import os
import struct
import socket  # used for converting host to network or the opposite direction
import datetime

SHOW_RULES =                "show_rules"
LOAD_RULES =                "load_rules"
SHOW_LOG =                  "show_log"
CLEAR_LOG =                 "clear_log"
SHOW_CONN_TABLE =           "show_conns"

RULES_DEVICE_FILE_PATH =    "/sys/class/fw/rules/rules"
SHOW_LOG_DEVICE_PATH =      "/dev/fw_log"
RESET_LOG_DEVICE_PATH =     "/sys/class/fw/log/reset"
CONN_DEVICE_FILE_PATH =     "/sys/class/fw/conns/conns"

DIRECTION_IN =  0x01
DIRECTION_OUT = 0x02
DIRECTION_ANY = DIRECTION_IN | DIRECTION_OUT

NF_DROP =   0
NF_ACCEPT = 1

PROT_ICMP =   1
PROT_TCP =    6
PROT_UDP =    17
PROT_OTHER =  255
PROT_ANY =    143

ACK_NO =    0x01
ACK_YES =   0x02
ACK_ANY =   ACK_NO | ACK_YES
MAX_RULES = 50

NUMBER_OF_ENTRIES_IN_A_RULE = 9
ANY_IP =                      0  
ANY_SUBNET =                  32  
MAX_PORT =                    65535

PORT_ANY =        0
PORT_ABOVE_1023 = 1023

REASON_FW_INACTIVE           = -1
REASON_NO_MATCHING_RULE      = -2
REASON_XMAS_PACKET           = -4
REASON_ILLEGAL_VALUE         = -6

CLOSED = 0
LISTEN = 1
SYN_RCVD = 2
ESTABLISHED = 3
FIN_WAIT_1 = 4
FIN_WAIT_2 = 5
TIME_WAIT_1 = 6
CLOSING = 7
SYN_SENT = 8
CLOSE_WAIT = 9
LAST_ACK = 10
ESTABLISHED_WAITING_FIN_RECEIVE = 11

#
# Gets the connections table data from the kernel space, makes it readable to the user and prints it
#
def show_conn_table():
    with open(CONN_DEVICE_FILE_PATH, "r") as f:
        conns = f.read()
        lines = conns.split("\n")
        conn_number = 0
        first_line = "line_number\tsrc_ip\t\tdst_ip\t\tsrc_port\tdst_port\tstate"
        print(first_line)
        
        for line in lines:
            line = line.strip()
            if line == '':
                break
                
            words = line.split(" ")
            
            conn_number += 1
            src_ip = value_to_table_ip(words[0])
            dst_ip = value_to_table_ip(words[1])
            src_port = value_to_table_port(words[2])
            dst_port = value_to_table_port(words[3])
            state = value_to_table_state(words[4])
            print(str(conn_number) + "\t\t" + \
                  src_ip + "\t" + \
                  dst_ip + "\t" + \
                  src_port + "\t\t" + \
                  dst_port + "\t\t" + \
                  state)




#
# Gets the rule data from the kernel space, makes it readable to the user and prints it
#
def show_rules():
    with open(RULES_DEVICE_FILE_PATH, "r") as f:
        rules = f.read()
        lines = rules.split("\n")
        for line in lines:
            line = line.strip()
            if line == '':
                break
                
            words = line.split(" ")
            rule_name = words[0]
            direction = value_to_table_direction(words[1])
            src_ip = value_to_table_ip(words[2])
            src_prefix_size = value_to_table_mask_size(words[3])
            dst_ip = value_to_table_ip(words[4])
            dst_prefix_size = value_to_table_mask_size(words[5])
            src_port = value_to_table_port(words[6])
            dst_port = value_to_table_port(words[7])
            protocol = value_to_table_protocol(words[8])
            ack = value_to_table_ack(words[9])
            action = value_to_table_action(words[10])

            src_ip_and_subnet = src_ip + "/" + src_prefix_size + " " if src_ip != "any" else src_ip + " "
            dst_ip_and_subnet = dst_ip + "/" + dst_prefix_size + " " if dst_ip != "any" else dst_ip + " "

            print(rule_name + " " + \
                  direction + " " + \
                  src_ip_and_subnet + \
                  dst_ip_and_subnet + \
                  protocol + " " + \
                  src_port + " " + \
                  dst_port + " " + \
                  ack + " " + \
                  action)

#
# Read rules from a file and write them to the kernel 
#
def load_rules(path_to_file):
    ready_rule_table = ""
    rules_count = 0
    with open(path_to_file, "r") as f:
        for line in f:
            rules_count += 1
            if rules_count > MAX_RULES:
                sys.exit("Error: number of rules exceeded maximum amount: " + str(MAX_RULES))

            rule = line.split(" ")
            if len(rule) != NUMBER_OF_ENTRIES_IN_A_RULE:
                sys.exit("Error: invalid rule: " + line)

            rule_name = rule[0]
            if len(rule_name) > 19:
                sys.exit("Error: Too long name: ", rule_name);
            rule_direction = direction_format(rule[1])

            rule_saddr, s_subnet_size = ip_format(rule[2])
            rule_daddr, d_subnet_size = ip_format(rule[3])

            s_mask = int(("1" * s_subnet_size + "0" * (32 - s_subnet_size)), 2)
            d_mask = int(("1" * d_subnet_size + "0" * (32 - d_subnet_size)), 2)

            rule_protocol = protocol_format(rule[4])
            rule_sport = port_format(rule[5])
            rule_dport = port_format(rule[6])
            rule_ack = ack_format(rule[7])
            rule_action = action_format(rule[8].lower())

            saddr_num = ip2long(rule_saddr)
            daddr_num = ip2long(rule_daddr)

            sport_num = port_format(str(rule_sport))
            dport_num = port_format(str(rule_dport))

            ready_rule_table += rule_name \
                                + " " + str(rule_direction) \
                                + " " + str(saddr_num) \
                                + " " + str(s_mask) \
                                + " " + str(s_subnet_size) \
                                + " " + str(daddr_num) \
                                + " " + str(d_mask) \
                                + " " + str(d_subnet_size) \
                                + " " + str(sport_num) \
                                + " " + str(dport_num) \
                                + " " + str(rule_protocol) \
                                + " " + str(rule_ack) \
                                + " " + str(rule_action) \
                                + "\n "
                            
    if ready_rule_table == "":
        sys.exit("Error: rule file seems to be empty!")
    ready_rule_table = ready_rule_table[:-2] # remove "\n " from last line
    if not os.path.exists(RULES_DEVICE_FILE_PATH):
        sys.exit("Error: could not find rules device file in path:" + RULES_DEVICE_FILE_PATH)
    with open(RULES_DEVICE_FILE_PATH, "w") as f:
        f.write(ready_rule_table)

#
# Formats the action to the kernel format (minimizing parsing done in the kernel)
#
def action_format(action):
    str_action = action.rstrip().lower()
    if str_action == "drop": return NF_DROP
    if str_action == "accept": return NF_ACCEPT

    sys.exit("Error: Invalid action: " + action)

#
# Formats the direction to the kernel format (minimizing parsing done in the kernel)
#
def direction_format(str_direction):
    direction = str_direction.lower()
    if direction == "in": return DIRECTION_IN
    if direction == "out": return DIRECTION_OUT
    if direction == "any": return DIRECTION_ANY

    sys.exit("Error in direction_format: unexpected value for direction. Got: " + str_direction)

#
# Formats the protocol to the kernel format (minimizing parsing done in the kernel)
#
def protocol_format(str_protocol):
    prot = str_protocol.lower()
    if prot == "any": return PROT_ANY
    if prot == "tcp": return PROT_TCP
    if prot == "udp": return PROT_UDP
    if prot == "icmp": return PROT_ICMP
    if prot == "other": return PROT_OTHER

    sys.exit("Error in protocol_format: unexpected value for protocol. Got: " + str_protocol)

#
# Formats the ack (flag) to the kernel format (minimizing parsing done in the kernel)
#
def ack_format(str_ack):
    ack = str_ack.lower()
    if ack == "no": return ACK_NO
    if ack == "yes": return ACK_YES
    if ack == "any": return ACK_ANY

    sys.exit("Error in ack_format: unexpected value for ack. Got: " + str_ack)

#
# Formats the port to the kernel format (minimizing parsing done in the kernel)
#
def port_format(str_port):
    if str_port == ">1023":
        return str(PORT_ABOVE_1023)
    elif str_port == "any":
        return str(PORT_ANY)
    elif str_port.isdigit():
        if int(str_port) > MAX_PORT or int(str_port) < 0 :
            sys.exit("Error:")
        return str_port
    else:
        sys.exit("Error in port_format: unexpected value for port. Got: " + str_port)

#
# Converts string ip (4 dotted decimal numbers) to littile endian number
#
def ip2long(ip):  # from stackoverflow
    if ip == ANY_IP:
        return ANY_IP
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


#
# Formats the ip to the kernel format (minimizing parsing done in the kernel)
#
def ip_format(ip_str):
    if ip_str.lower() == "any":
        return ANY_IP, ANY_SUBNET
    else:
        ip_parts = ip_str.split("/")
        if len(ip_parts) != 2:
            sys.exit("Error: invalid ip: " + ip_str)
        ip = ip_parts[0]
        prefix = int(ip_parts[1])
        if prefix > 32 or prefix < 0:
            sys.exit("Error: invalid prefix size: " + ip_parts[1])
        return ip, prefix

#
# Receives the log data from the kernel, makes it readable and prints it
#
def show_log():
    with open(SHOW_LOG_DEVICE_PATH, "r") as f: 
        log_rows = f.read()
        lines = log_rows.split("\n")
        if lines[-1] == "":
            lines = lines[:-1]
        lines.sort(key=sort_by_timestamp) # sort log by time
        first_line = "timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\tdst_port\tprotocol\thooknum\t\taction\t\treason\t\t\t\tcount"
        print(first_line)
        for line in lines:
            if line.strip() == '':
                break
            words = line.split(" ")
            timestamp = datetime.datetime.fromtimestamp(int(words[0])).strftime('%d/%m/%Y %H:%M:%S')
            src_ip = value_to_table_ip(words[1])
            dst_ip = value_to_table_ip(words[2])
            src_port = value_to_table_port(words[3])
            dst_port = value_to_table_port(words[4])
            protocol = value_to_table_protocol(words[5]).lower()
            if protocol != "udp" and protocol != "tcp": # for our uses, assumes only tcp and udp protocols uses ports field
                src_port = "N/A"
                dst_port = "N/A"
            hooknum = 1 # we only hook to pre routing hook
            action = value_to_table_action(words[6])
            reason = value_to_table_reason(words[7])
            
            if reason.isdigit():
                reason += "\t\t\t\t"
            else:
                reason += "\t\t"
                
            count = words[8]
            if action == None: 
                break
            print(timestamp + "\t" + \
                  src_ip + "\t" + \
                  dst_ip + "\t" + \
                  src_port + "\t\t" + \
                  dst_port + "\t\t" + \
                  protocol + "\t\t" + \
                  str(hooknum) + "\t\t" + \
                  action + "\t\t" + \
                  reason + \
                  count)
            
#
# Sort the timestamps in ascending order
#
def sort_by_timestamp(line):
    timestamp = int(line.split(" ")[0])
    return timestamp

#
# Sends the command to the kernel to clean the log
#
def clear_log():
    with open(RESET_LOG_DEVICE_PATH, "w") as f:
        f.write("CLEAR")

#
# Formats the reason from the kernel format to user readable 
#
def value_to_table_reason(reason):
    int_reason = int(reason)
    if int_reason == REASON_FW_INACTIVE:
        return "REASON_FW_INACTIVE"
    elif int_reason == REASON_NO_MATCHING_RULE:
        return "REASON_NO_MATCHING_RULE"
    elif int_reason == REASON_XMAS_PACKET:
        return "REASON_XMAS_PACKET"
    elif int_reason == REASON_ILLEGAL_VALUE:
        return "REASON_ILLEGAL_VALUE"
    else:
        return reason

#
# Formats the mask size from the kernel format to user readable 
#
def value_to_table_mask_size(mask_size):
    return mask_size

#
# Formats the protocol from the kernel format to user readable 
#
def value_to_table_protocol(protocol):
    int_protocol = int(protocol)
    if int_protocol == PROT_ICMP:
        return "ICMP"
    elif int_protocol == PROT_TCP:
        return "TCP"
    elif int_protocol == PROT_UDP:
        return "UDP"
    elif int_protocol == PROT_OTHER:
        return "other"
    elif int_protocol == PROT_ANY:
        return "any"

#
# Formats the ack (flag) from the kernel format to user readable 
#
def value_to_table_ack(ack):
    int_ack = int(ack)
    if int_ack == ACK_NO:
        return "no"
    elif int_ack == ACK_YES:
        return "yes"
    elif int_ack == ACK_ANY:
        return "any"

#
# Formats the action from the kernel format to user readable 
#
def value_to_table_action(action):
    int_action = int(action)
    if int_action == NF_DROP:
        return "drop"
    elif int_action == NF_ACCEPT:
        return "accept"

#
# Formats the direction from the kernel format to user readable 
#
def value_to_table_direction(direction):
    direction_num = int(direction)
    if direction_num == 1: return "in"
    if direction_num == 2: return "out"
    if direction_num == 3: return "any"

    sys.exit("Error: got invalid value for direction: " + direction)


#
# Formats the action from the kernel format to user readable 
# @pre: receives ip in big endian
def value_to_table_ip(ip):
    big_end_ip = int(ip)
    lil_end_ip = socket.inet_ntoa(struct.pack('<L', big_end_ip))
    if big_end_ip == ANY_IP:
        return "any"
    else:
        return lil_end_ip

#
# Formats the state from the kernel format to user readable (tcp states)
#
def value_to_table_state(state):
    state_num = int(state)
    if state_num == CLOSED: return "CLOSED"
    if state_num == LISTEN: return "LISTEN"
    if state_num == SYN_RCVD: return "SYN_RCVD"
    if state_num == ESTABLISHED: return "ESTABLISHED"
    if state_num == FIN_WAIT_1: return "FIN_WAIT_1"
    if state_num == FIN_WAIT_2: return "FIN_WAIT_2"
    if state_num == TIME_WAIT_1: return "TIME_WAIT_1"
    if state_num == CLOSING: return "CLOSING"
    if state_num == SYN_SENT: return "SYN_SENT"
    if state_num == CLOSE_WAIT: return "CLOSE_WAIT"
    if state_num == LAST_ACK: return "LAST_ACK"

    sys.exit("Error: got invalid value for state: " + state)
    
    
#
# Formats the action from the kernel format to user readable 
# @pre: receives port in big endian
def value_to_table_port(port):
    big_end_port = int(port)
    lil_end_port = socket.ntohs(big_end_port)
    if lil_end_port == PORT_ANY:
        return "any"
    elif lil_end_port == PORT_ABOVE_1023:
        return ">1023"
    else:
        return str(lil_end_port)


#
# Calls the appropriate function according to the user input
#
if __name__ == '__main__':
    args_size = len(sys.argv)
    if args_size == 1:
        sys.exit("Usage: python main.py <show_conns> or \npython main.py <show_rules> or \npython main.py <show_log> or \npython main.py <clear_log> or \npython main.py <load_rules> <path_to_rules_file>")
    first_arg = sys.argv[1]
    if first_arg != LOAD_RULES and args_size > 2:
        sys.exit("Error: Too many arguments were given!")

    if first_arg == SHOW_RULES:
        show_rules()
    elif first_arg == LOAD_RULES:
        if args_size != 3:
            sys.exit("Error: invalid arguments!")
        path_to_rules_file = sys.argv[2]
        if not os.path.exists(path_to_rules_file):
            sys.exit("Error: rules file does not exist!")
        load_rules(path_to_rules_file)
    elif first_arg == SHOW_LOG:
        show_log()
    elif first_arg == CLEAR_LOG:
        clear_log()
    elif first_arg == SHOW_CONN_TABLE:
        show_conn_table()
    else:
        sys.exit("Error: Invalid argument!")
