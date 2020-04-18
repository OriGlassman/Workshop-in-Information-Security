#ifndef SECWS_STATEFUL_FW_H
#define SECWS_STATEFUL_FW_H

#include "fw.h"

struct conn_t_lst {
    struct conn_t_lst* next;
    conn_row_t con_row;
};

void create_new_conn_entry(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

void conn_table_clean_up(void);

int check_connection_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, tcp_flags flags);

int show_connection_table(char* buf);

int doesnt_exist_in_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

ssize_t sysfs_handle_conn_table(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

struct conn_t_lst* find_connection_by_mitm_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 mitm_port);

int is_http_connection(__be16 dst_port);
int is_ftp_connection(__be16 dst_port);
int is_thinvnc_connection(__be16 dst_port);
int is_smtp_connection(__be16 dst_port);

#endif //SECWS_STATEFUL_FW_H
