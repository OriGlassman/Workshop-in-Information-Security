#include "stateful_fw.h"
#include "fw.h"

#define MAX_STRING_SIZE_CONN_ROW (100)
#define NUM_WORDS_4_TUPLE (4)
#define MAX_CMD_LENGTH (6)
#define MINIMAL_LINE_SIZE (26)


static void assign_conn_entry(struct conn_t_lst* conn_entry, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state, __be16 mitm_port);
static int check_and_update_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, tcp_flags flags);
static void free_list(void);
static struct conn_t_lst* find_relevant_connection_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);
static __be16 get_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);
static int set_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __be16 mitm_port);
static void clean_entry(struct conn_t_lst *deleted_entry);


static struct conn_t_lst* conn_head = NULL;
static struct conn_t_lst* start_conn_lst = NULL;

/*
* Creates two way connections in the connection table (stateful firewall)
*/
void create_new_conn_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    struct conn_t_lst* first_way_entry;
    struct conn_t_lst* return_way_entry;
    
    first_way_entry = (struct conn_t_lst*) kmem_cache_alloc(conn_cache, GFP_ATOMIC);
    return_way_entry = (struct conn_t_lst*) kmem_cache_alloc(conn_cache, GFP_ATOMIC);

    if (first_way_entry == NULL || return_way_entry == NULL){
        printk(KERN_INFO "kmem_cache_alloc failed in create_new_conn_entry");
        return;
    }
    assign_conn_entry(first_way_entry, src_ip, dst_ip, src_port, dst_port, SYN_SENT, 0);
    assign_conn_entry(return_way_entry, dst_ip, src_ip, dst_port, src_port, LISTEN, 0);
}

/*
* Assign values to the connection entry
*/
static void assign_conn_entry(struct conn_t_lst* conn_entry, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state, __be16 mitm_port){
    conn_entry->con_row.src_ip = src_ip;
    conn_entry->con_row.dst_ip = dst_ip;
    conn_entry->con_row.src_port = src_port;
    conn_entry->con_row.dst_port = dst_port;
    conn_entry->con_row.state = state;
    conn_entry->con_row.mitm_port = mitm_port;
    conn_entry->next = NULL;

    if (conn_head != NULL){
        conn_head->next = conn_entry;
        conn_head = conn_entry;
    }
    else {
        start_conn_lst = conn_entry;
        conn_head = start_conn_lst;
    }
}

/*
* Clears the connection table and cleans the kmem cache
*/
void conn_table_clean_up(void){
    free_list(); 
    if (conn_cache != NULL){
        kmem_cache_destroy(conn_cache);
    }
}

/*
* Pass the connection table to the user-space
*/
int show_connection_table(char* buf){
    struct conn_t_lst* curr_node;
    char* conn_output;
    char line[MAX_STRING_SIZE_CONN_ROW+1] = {0};
    int bytes_written;
    int size = 0;
    curr_node = start_conn_lst;
    while (curr_node != NULL){
        size +=1;
        curr_node = curr_node->next;
    }
    
    if (size == 0){
        return 0;
    }
    conn_output = kmalloc(size*MAX_STRING_SIZE_CONN_ROW*sizeof(float), GFP_ATOMIC);
    curr_node = start_conn_lst;
    while (curr_node != NULL){
        scnprintf(line, MAX_STRING_SIZE_CONN_ROW, "%u %u %u %u %u\n", 
                                       curr_node->con_row.src_ip,
                                       curr_node->con_row.dst_ip,
                                       curr_node->con_row.src_port,
                                       curr_node->con_row.dst_port,
                                       curr_node->con_row.state
                  );
        strncat(conn_output, line, MAX_STRING_SIZE_CONN_ROW);        
        curr_node = curr_node->next;
    }
    
    bytes_written = scnprintf(buf, PAGE_SIZE, "%s", conn_output);
    kfree(conn_output);
    return bytes_written;
}

/*
* Wrapper to check for tcp state validity in the connection table
*/
int check_connection_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, tcp_flags flags) {
    if (check_and_update_conn_table(src_ip, dst_ip, src_port, dst_port, flags) == 1){
        return NF_ACCEPT;
    }
    else {
        return NF_DROP;
    }
}

/*
* Checks if the packet tcp state is according to the tcp state machinie
*/
static int check_and_update_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, tcp_flags flags){
    struct conn_t_lst* entry_other_way;
    struct conn_t_lst* entry_first_way;
        
    if ( src_ip == BE_SERVER_IP && (src_port == BE_HTTP_PORT ||
                                     src_port == BE_FTP_PORT || src_port == BE_THINVNC_PORT ||
                                     src_port == BE_SMTP_PORT)){
        entry_first_way = find_connection_by_mitm_port(src_ip, dst_ip, src_port, dst_port); //dst_port here should be the MITM port
        if (entry_first_way == NULL) return 0;
        entry_other_way = find_relevant_connection_entry(dst_ip, src_ip, entry_first_way->con_row.dst_port, src_port);  
    } else {
        entry_first_way = find_relevant_connection_entry(src_ip, dst_ip, src_port, dst_port);
        entry_other_way = find_relevant_connection_entry(dst_ip, src_ip, dst_port, src_port);
    }

    if (entry_first_way == NULL || entry_other_way == NULL){ // no matching connection rule
        return 0;
    }
    else {
        if (flags.rst){
            clean_entry(entry_first_way);
            clean_entry(entry_other_way);
            return 1;
        }
        switch (entry_first_way->con_row.state){ 
            case LISTEN:
                if (flags.ack && flags.syn){
                    entry_first_way->con_row.state = SYN_RCVD;
                    return 1;
                }
                break;
            case SYN_RCVD:
                if (flags.fin) {
                    entry_first_way->con_row.state = FIN_WAIT_1;
                    return 1;
                } else if (flags.ack){
                    entry_first_way->con_row.state = ESTABLISHED;
                    return 1;
                }
                break;
            case SYN_SENT:
                if (flags.ack) {
                    entry_first_way->con_row.state = ESTABLISHED;
                    return 1;
                }
                break;
            case ESTABLISHED:
                if (flags.fin && flags.ack){
                    entry_first_way->con_row.state = LAST_ACK;
                    entry_other_way->con_row.state = CLOSE_WAIT;
                    return 1;
                }
                else if (flags.fin){ 
                    entry_first_way->con_row.state = FIN_WAIT_1;
                    entry_other_way->con_row.state = CLOSE_WAIT;
                    return 1;
                } else if (flags.ack) {
                    return 1; //normal flow between two sides
                }
                break;
            case FIN_WAIT_2:
                if (flags.ack && flags.fin){
                    entry_first_way->con_row.state = LAST_ACK;
                    return 1;
                }
                else if (flags.ack){
                    return 1;
                }
                break;
            case CLOSE_WAIT:
                if (flags.ack && flags.fin){
                    entry_first_way->con_row.state = LAST_ACK;
                    return 1;
                }
                else if (flags.ack){
                    entry_first_way->con_row.state = FIN_WAIT_2;
                    return 1;
                }
                else if (flags.fin){
                    entry_first_way->con_row.state = LAST_ACK;
                    entry_other_way->con_row.state = TIME_WAIT_1;
                    return 1;
                }
                break;
            case LAST_ACK:
                if (flags.ack){
                    entry_first_way->con_row.state = CLOSED;
                    entry_other_way->con_row.state = CLOSED;
                    clean_entry(entry_first_way);
                    clean_entry(entry_other_way);
                    return 1;
                }
            case TIME_WAIT_1:
                if (flags.ack){
                    entry_first_way->con_row.state = CLOSED;
                    clean_entry(entry_first_way);
                    return 1;
                }
                break;
            default:
                break;
        }
        return 0;
    }
}

/*
* Removes a single entry from the connection table
*/
static void clean_entry(struct conn_t_lst *deleted_entry) {
    struct conn_t_lst *curr = start_conn_lst, *prev = NULL;

    if (curr != NULL && curr == deleted_entry){
        start_conn_lst = curr->next;
        kmem_cache_free(conn_cache, curr);
        if (start_conn_lst == NULL){
            conn_head = NULL;
        }
        return;
    }

    while (curr != NULL && curr != deleted_entry){
        prev = curr;
        curr = curr->next;
    }
    if (curr == NULL || prev == NULL) { // no entry in the linked list
        return;
    }
    prev->next = curr->next;
    if (prev->next == NULL){
        conn_head = prev;
    }
    kmem_cache_free(conn_cache, curr);
}

/*
* Finds the relevant connection entry by the 4-tuple
*/
static struct conn_t_lst* find_relevant_connection_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port) {
    struct conn_t_lst* curr_node = start_conn_lst;

    while (curr_node != NULL){
        if (curr_node->con_row.src_ip == src_ip &&
                curr_node->con_row.dst_ip == dst_ip &&
                curr_node->con_row.src_port == src_port &&
                curr_node->con_row.dst_port == dst_port)
        {
            return curr_node; // found matching connection
        }
        curr_node = curr_node->next;
    }

    return NULL; // didn't find matching connection
}

/*
* Finds the relevant connection entry by the help of the man in the middle port
*/
struct conn_t_lst* find_connection_by_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 mitm_port) {
    struct conn_t_lst* curr_node = start_conn_lst;

    while (curr_node != NULL){
        if (curr_node->con_row.src_ip == src_ip &&
                curr_node->con_row.dst_ip == dst_ip &&
                curr_node->con_row.src_port == src_port &&
                curr_node->con_row.mitm_port == mitm_port)
        {
            return curr_node; // found matching connection
        }
        curr_node = curr_node->next;
    }

    return NULL; // didn't find matching connection
}

/*
* Frees every connection in the linked list
*/
static void free_list(void) {
    struct conn_t_lst* temp;

    while (start_conn_lst != NULL){
        temp = start_conn_lst;
        start_conn_lst = start_conn_lst->next;
        kmem_cache_free(conn_cache, temp);
    }
}

/*
* Check if a connection entry already exists
*/
int doesnt_exist_in_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    if (find_relevant_connection_entry(src_ip, dst_ip, src_port, dst_port) == NULL){
        return 1;
    } else {
        return 0;
    }
}

/*
* Get the man in the middle port for the certain connection
*/
static __be16 get_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    struct conn_t_lst* conn = find_relevant_connection_entry(src_ip, dst_ip, src_port, dst_port);
    if (conn == NULL) {
        return 0;
    } else {
        return conn->con_row.mitm_port;
    }
}

/*
* Set the man in the middle port for the certain connection
*/
static int set_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __be16 mitm_port){
    struct conn_t_lst* conn;

    if (mitm_port == 0) {
        pr_info("Invalid mitm port: 0");
        return 1;
    }
    conn = find_relevant_connection_entry(src_ip, dst_ip, src_port, dst_port);
    if (conn == NULL){
        return 1; // assumes here that port "1" is not used as mitm port
    } else {
        conn->con_row.mitm_port = mitm_port;
        return 0;
    }
}

/*
* Handle the commands from the user-space to interact with the connection table
*/
ssize_t sysfs_handle_conn_table(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    __be32 src_ip, dst_ip; __be16 src_port,  dst_port, mitm_port;
    char* tok, *end, *user_input;
    char cmd[MAX_CMD_LENGTH+1] = {0};
    int command_len, res_value;

    if (count < MINIMAL_LINE_SIZE || count > PAGE_SIZE || strlen(buf) != count){ 
        printk(KERN_INFO "Invalid user input");
        return -EINVAL;
    }
    user_input = kmalloc((sizeof(char) * count) + sizeof(char), GFP_KERNEL);
    if (user_input == NULL){
        printk(KERN_INFO "kmalloc returned null");
        return 1;
    }

    memcpy(user_input, buf, count);
    *(user_input+count) = '\0';
    tok = user_input; end = user_input;
    tok = strsep(&end, " ");
    if (tok == NULL) {
        kfree(user_input);
        printk(KERN_INFO "strsep returned null");
        return 1;
    }

    if (strcmp(tok, "get") != 0 && strcmp(tok, "set") != 0 && strcmp(tok, "create") != 0) {
        kfree(user_input);
        printk(KERN_INFO "No get,set or create at the start of command");
        return 1;
    }
    strcpy(cmd, tok); // strcpy is safe because we know it's either "get" or "set" or "create
    tok=end;

    for (command_len = 0; command_len < NUM_WORDS_4_TUPLE; command_len++){
        tok = strsep(&end, " ");
        if (tok == NULL) {
            kfree(user_input);
            printk(KERN_INFO "strsep returned null");
            return 1;
        }
        switch (command_len){
            case 0:
                res_value = kstrtou32(tok, 10, &src_ip);
                if (res_value == -EINVAL){
                    printk(KERN_INFO "Error: got invalid src_ip value: %s", tok);
                    kfree(user_input);
                    return -EINVAL;
                }
                src_ip = cpu_to_be32(src_ip);
                break;

            case 1:
                res_value = kstrtou16(tok, 10, &src_port);
                if (res_value == -EINVAL){
                    printk(KERN_INFO "Error: got invalid src_port value: %s", tok);
                    kfree(user_input);
                    return -EINVAL;
                }
                src_port = cpu_to_be16(src_port);
                break;

            case 2:
                res_value = kstrtou32(tok, 10, &dst_ip);
                if (res_value == -EINVAL){
                    printk(KERN_INFO "Error: got invalid dst_ip value: %s", tok);
                    kfree(user_input);
                    return -EINVAL;
                }
                dst_ip = cpu_to_be32(dst_ip);
                break;

            case 3:
                res_value = kstrtou16(tok, 10, &dst_port);
                if (res_value == -EINVAL){
                    printk(KERN_INFO "Error: got invalid dst_port value: %s", tok);
                    kfree(user_input);
                    return -EINVAL;
                }
                dst_port = cpu_to_be16(dst_port);
                break;
        }
        tok=end;
    }
    if (strcmp(cmd, "get") == 0) {
        kfree(user_input);
        return get_mitm_port(src_ip, dst_ip, src_port, dst_port);
    } else if (strcmp(cmd, "create") == 0){
        kfree(user_input);
        create_new_conn_entry(src_ip, dst_ip, src_port, dst_port);
        return 0;
    } else if (strcmp(cmd, "set") == 0) {
        tok = strsep(&end, " ");
        if (tok == NULL) {
            kfree(user_input);
            printk(KERN_INFO "strsep returned null");
            return 1;
        }
        // fetch mitm_port
        res_value = kstrtou16(tok, 10, &mitm_port);
        if (res_value == -EINVAL){
            printk(KERN_INFO "Error: got invalid mitm_port value: %s", tok);
            kfree(user_input);
            return -EINVAL;
        }
        mitm_port = cpu_to_be16(mitm_port);
        kfree(user_input);
        return set_mitm_port(src_ip, dst_ip, src_port, dst_port, mitm_port);
    }
    return -1; // should not get here
}

/*
* Checks if the dst_port is relevant to http connection
*/
int is_http_connection(__be16 dst_port){
    struct conn_t_lst* conn = find_relevant_connection_entry(BE_SERVER_IP, BE_CLIENT_IP, BE_HTTP_PORT, dst_port);
    return conn != NULL;
}   

/*
* Checks if the dst_port is relevant to ftp connection
*/
int is_ftp_connection(__be16 dst_port){
    struct conn_t_lst* conn = find_relevant_connection_entry(BE_SERVER_IP, BE_CLIENT_IP, BE_FTP_PORT, dst_port);
    return conn != NULL;
}

/*
* Checks if the dst_port is relevant to thinvnc connection
*/
int is_thinvnc_connection(__be16 dst_port){
    struct conn_t_lst* conn = find_relevant_connection_entry(BE_SERVER_IP, BE_CLIENT_IP, BE_THINVNC_PORT, dst_port);
    return conn != NULL;
}

/*
* Checks if the dst_port is relevant to smtp connection
*/
int is_smtp_connection(__be16 dst_port) {
    struct conn_t_lst* conn = find_relevant_connection_entry(BE_SERVER_IP, BE_CLIENT_IP, BE_SMTP_PORT, dst_port);
    return conn != NULL;
}