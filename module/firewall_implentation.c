#include "firewall_implentation.h"

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/time.h>
#include <net/tcp.h>
#include "logs_implementation.h"
#include "stateful_fw.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ori Glassman");


static int loopback_packet(__be32 dst_ip);
static __u8 does_rule_match(rule_t rule_table[MAX_RULES], size_t rule_count, 
                           const struct net_device *in, __u8 protocol, __be32 src_ip, __be32 dst_ip,
                           __be16 src_port, __be16 dst_port, ack_t ack_flag, reason_t* reason);
static void fix_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header, struct sk_buff *skb);
static void out_fix_checksum(struct sk_buff *skb);

/*
* This is the firewall logic: it inspects the packets and make a decision according to the rule table
*/
int firewall(log_row_t** dynamic_log, log_row_t* single_entry_log, size_t* log_count,
                      size_t* total_alloc_size_log,
                      rule_t rule_table[MAX_RULES], size_t rule_count,
                      const struct net_device *in,
                      struct sk_buff *skb)
{
    __be32 src_ip, dst_ip;
    __be16 src_port, dst_port;
    __u8 protocol; 
    __u8 action;
    __u16 ack;
    ack_t ack_flag;
    reason_t reason;
    tcp_flags tcp_flags;
    struct timespec ts;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct iphdr* ip_header;
    int ret;
    struct conn_t_lst* ret_value; 
    
    if (skb == NULL) return NF_ACCEPT;
    ip_header = (struct iphdr*) skb_network_header(skb);
    if (ip_header == NULL) return NF_ACCEPT;
    protocol = ip_header->protocol;
    src_ip = ip_header->saddr;
    dst_ip = ip_header->daddr;
    getnstimeofday(&ts);
    
    // check for ipv6 and accept without logging
    if ((*((char*)ip_header) & 0x06) == IPV6_VERSION){
        return NF_ACCEPT;
    }
    
    // check for loopback packet and accept without logging
    if (loopback_packet(dst_ip)){
        return NF_ACCEPT;
    }

    if (protocol == PROT_TCP){
        tcp_header = (struct tcphdr*)((__u32 *)ip_header+ ip_header->ihl);
        if (tcp_header == NULL) return NF_DROP;
        src_port = tcp_header->source;
        dst_port = tcp_header->dest;
        ack = tcp_header->ack;
        tcp_flags.ack = ack;
        tcp_flags.syn = tcp_header->syn;
        tcp_flags.fin = tcp_header->fin;
        tcp_flags.rst = tcp_header->rst;


        if (tcp_header->fin == 1 && tcp_header->psh == 1 && tcp_header->urg == 1){ // XMAS packet
            action = NF_DROP;
            reason = REASON_XMAS_PACKET;
            ret = write_to_log(dynamic_log, single_entry_log, log_count, total_alloc_size_log,
                               ts.tv_sec, protocol,  action,
                               src_ip,  dst_ip,  src_port,  dst_port, reason);
            if (ret == -EINVAL){
                return -EINVAL;
            }
            return NF_DROP;
        }
        

        if (tcp_flags.ack == 1 || tcp_flags.fin == 1) {
            action = check_connection_table(src_ip, dst_ip, src_port, dst_port, tcp_flags);
        } else {
            ack_flag = ACK_NO;
            if (src_ip == BE_SERVER_IP && (src_port == BE_HTTP_PORT ||
                                           src_port == BE_FTP_PORT || 
                                           src_port == BE_THINVNC_PORT ||
                                          src_port == BE_SMTP_PORT)) { 
                ret_value = find_connection_by_mitm_port(src_ip, dst_ip, src_port, dst_port); //dst_port should be the mitm_port
                if (ret_value == NULL){
                    return NF_DROP;
                } else {
                    action = NF_ACCEPT;
                }   
            } 
            else {
                if (src_port == BE_FTP_DATA_PORT){
                    action = NF_ACCEPT;
                } else {
                    action = does_rule_match(rule_table, rule_count, in, protocol, src_ip, dst_ip, src_port, dst_port, ack_flag, &reason);
                }
                ret = write_to_log(dynamic_log, single_entry_log, log_count, total_alloc_size_log,
                                   ts.tv_sec, protocol,  action,
                                   src_ip,  dst_ip,  src_port,  dst_port, reason);
                if (action == NF_ACCEPT && doesnt_exist_in_table(src_ip, dst_ip, src_port, dst_port)){
                    if (src_port != BE_FTP_DATA_PORT){
                        create_new_conn_entry(src_ip, dst_ip, src_port, dst_port); // creates both ways entries
                    } 
                }
                if (ret == -EINVAL){
                    return -EINVAL;
                }
            }
        } 
        
        // client to server inbound
        if (action == NF_ACCEPT && src_ip == BE_CLIENT_IP && dst_ip == BE_SERVER_IP &&
                    (dst_port == BE_HTTP_PORT || dst_port == BE_FTP_PORT ||
                     dst_port == BE_THINVNC_PORT || dst_port == BE_SMTP_PORT)) {
            if (dst_port == BE_HTTP_PORT){
                tcp_header->dest = BE_MITM_HTTP_PORT;
            } else if (dst_port == BE_THINVNC_PORT){
                tcp_header->dest = BE_MITM_THINVNC_PORT;
            } else if (dst_port == BE_SMTP_PORT){
                tcp_header->dest = BE_MITM_SMTP_PORT;
            } else {
                tcp_header->dest = BE_MITM_FTP_PORT;
            }
            ip_header->daddr = BE_FW_IP_HOST1;
            // fix checksum
            fix_checksum(ip_header, tcp_header, skb);
        } else if (action == NF_ACCEPT && src_ip == BE_SERVER_IP  &&
                    (src_port == BE_HTTP_PORT || src_port == BE_FTP_PORT ||
                     src_port == BE_THINVNC_PORT || src_port == BE_SMTP_PORT )) { //Server to client inbound
            ip_header->daddr = BE_FW_IP_HOST2; 
            fix_checksum(ip_header, tcp_header, skb);
        }
        return action;
    }
    else if (protocol == PROT_ICMP){
        action = does_rule_match(rule_table, rule_count, in, protocol, src_ip, dst_ip, 0, 0, 0, &reason);
        ret = write_to_log(dynamic_log, single_entry_log, log_count, total_alloc_size_log,
                        ts.tv_sec, protocol,  action,
                         src_ip,  dst_ip,  0,  0, reason);
       if (ret == -EINVAL){
                return -EINVAL;
        }
        return action;
    }
    else if (protocol == PROT_UDP){
        udp_header = (struct udphdr*)((__u32 *)ip_header+ ip_header->ihl);
        src_port = udp_header->source;
        dst_port = udp_header->dest;
  
        action = does_rule_match(rule_table, rule_count, in, protocol, src_ip, dst_ip, src_port, dst_port, 0, &reason);
        getnstimeofday(&ts);
        ret = write_to_log(dynamic_log, single_entry_log, log_count, total_alloc_size_log,
                        ts.tv_sec, protocol,  action,
                         src_ip,  dst_ip,  src_port,  dst_port, reason);
        if (ret == -EINVAL){
            return -EINVAL;
        }
        return action;
    }
    else {
        return NF_ACCEPT;
    } 
    return -EFAULT; // should not get here
}

/*
* Fixes the checksum for inbound packets
*/
static void fix_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header, struct sk_buff *skb) {
    int tcplen;
    if (skb == NULL || ip_header == NULL || tcp_header == NULL) return;
    tcplen = (skb->len - ((ip_header->ihl )<< 2));
    tcp_header->check=0;
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
    skb->ip_summed = CHECKSUM_NONE; //stop offloading
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
}

/*
* Fixes the checksum for outbound packets (function taken from stackoverflow)
*/
static void out_fix_checksum(struct sk_buff *skb) {
    unsigned int tcplen;
    struct iphdr *ip_header;
    struct tcphdr *tcpHdr;
    
    if (skb == NULL) return;
    ip_header = ip_hdr(skb);
    if (ip_header == NULL) return;
    skb->ip_summed = CHECKSUM_NONE;
    //skb->csum_valid =0;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    if (skb_is_nonlinear(skb)){
        skb_linearize(skb);
        skb_shinfo(skb)->gso_size = 0; // a fix to kernel warning from internet
    }
    tcpHdr = tcp_hdr(skb);
    if (tcpHdr == NULL) return;
    skb->csum=0;
    tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
    tcpHdr->check=0;
    tcpHdr->check= tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char*)tcpHdr, tcplen, 0));
}


/*
* Utility function to check if a there is a rule match the packet
*/
static __u8 does_rule_match(rule_t rule_table[MAX_RULES], size_t rule_count, 
                           const struct net_device *in, __u8 protocol, __be32 src_ip, __be32 dst_ip,
                           __be16 src_port, __be16 dst_port, ack_t ack_flag, reason_t* reason) {
    __be32 masked_src_ip;
    __be32 rule_masked_src_ip;
    __be32 masked_dst_ip;
    __be32 rule_masked_dst_ip; 
    int i;
    
    if (rule_count == 0){ // I thought the intention is that if rule table was not loaded yet, to accept everything
        *reason = REASON_FW_INACTIVE;
        return NF_ACCEPT;
    }
        
    for (i = 0; i < rule_count; i++){
        if (strcmp(rule_table[i].rule_name, "default") == 0){
            *reason = REASON_NO_MATCHING_RULE; 
            return NF_DROP;
        }
        //Direction
        if (rule_table[i].direction == DIRECTION_ANY){
            
        }
        else {
            if (rule_table[i].direction == DIRECTION_IN){
                if (strcmp(in->name, OUT_NET_DEVICE_NAME) != 0){
                    continue;
                }
            }
            else if (rule_table[i].direction == DIRECTION_OUT){
                if (strcmp(in->name, IN_NET_DEVICE_NAME) != 0){
                    continue;
                }
            }
        }
        
        // Protocol
        if (rule_table[i].protocol != PROT_ANY){
            if (rule_table[i].protocol != protocol){
                continue;
            }
            // Check ack bit
            if (protocol == PROT_TCP && rule_table[i].ack != ACK_ANY){
                if (ack_flag != rule_table[i].ack){
                    continue;
                }
            }
        }
        
        //Ports
        if (protocol == PROT_TCP || protocol == PROT_UDP){
            if (rule_table[i].src_port != 0){ // 0 means port is "any"
                if (rule_table[i].src_port == PORT_ABOVE_1023_BE){
                    if ( (src_port & 0xFC) == 0) { // if there's a bit on in pos 2-8 (BE), meaning port in LE is higher than 1023
                        continue;
                    }
                }
                else if (rule_table[i].src_port != src_port){
                    continue;
                }
            }
            if (rule_table[i].dst_port != 0){
                if (rule_table[i].dst_port == PORT_ABOVE_1023_BE){
                    if ((dst_port & 0xFC ) == 0){
                        continue;
                    }
                }
                else if (rule_table[i].dst_port != dst_port){
                    continue;
                }
            }
        }
        
        // IP
        if (rule_table[i].src_ip != 0){
            masked_src_ip = src_ip & rule_table[i].src_prefix_mask;
            rule_masked_src_ip = rule_table[i].src_ip & rule_table[i].src_prefix_mask; 
            if (masked_src_ip != rule_masked_src_ip){
                continue;
            }
        }
        
        if (rule_table[i].dst_ip != 0){
            masked_dst_ip = dst_ip & rule_table[i].dst_prefix_mask;
            rule_masked_dst_ip = rule_table[i].dst_ip & rule_table[i].dst_prefix_mask;         
            if (masked_dst_ip != rule_masked_dst_ip){
                continue;
            }
        }
        
        // If we got here it means the rule matches the packet
        *reason = i;
        return rule_table[i].action; 
    }
    *reason = REASON_NO_MATCHING_RULE;
    return NF_DROP; // Gets here only if there's no default rule table and no other rule matched the packet
}

/*
* Checks if the destination ip starts with "127" in big endian (avoids casting)
*/
static int loopback_packet(__be32 dst_ip){
    if ( (dst_ip & 0x000000FF) == 0x7F){
        return 1;
    }
    else {
        return 0;
    }
}

/*
* Fixes ip and tcp fields according to the man in the middle program
*/
unsigned int fix_packet_fields(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff*))
{
    __be32 src_ip, dst_ip;
    __be16 src_port, dst_port;
    __u8 protocol;

    struct tcphdr* tcp_header;
    struct iphdr* ip_header;
    
    if (skb == NULL) return NF_ACCEPT;
    ip_header = (struct iphdr*) skb_network_header(skb);
    if (ip_header == NULL) return NF_ACCEPT;
    protocol = ip_header->protocol;
    src_ip = ip_header->saddr;
    dst_ip = ip_header->daddr;
    if (protocol == PROT_TCP){ 
        tcp_header = (struct tcphdr*)((__u32 *)ip_header+ ip_header->ihl);
        if (tcp_header == NULL) return NF_DROP;
        src_port = tcp_header->source;
        dst_port = tcp_header->dest;
        
        //Client to server
        if (dst_ip == BE_SERVER_IP && (dst_port == BE_HTTP_PORT || dst_port == BE_FTP_PORT || dst_port == BE_THINVNC_PORT ||                dst_port == BE_SMTP_PORT)){
            ip_header->saddr = BE_CLIENT_IP;
            out_fix_checksum(skb);
        } //Server to client
        else if (src_ip == BE_FW_IP_HOST1 && dst_ip == BE_CLIENT_IP){
            ip_header->saddr = BE_SERVER_IP;
            
            if (is_http_connection(dst_port)){
                tcp_header->source = BE_HTTP_PORT;
            } else if (is_ftp_connection(dst_port)) {
                tcp_header->source = BE_FTP_PORT;
            } else if (is_thinvnc_connection(dst_port)){
                tcp_header->source = BE_THINVNC_PORT;
            } else if (is_smtp_connection(dst_port)) {
                tcp_header->source = BE_SMTP_PORT;
            } else {
                if (src_port == BE_MITM_FTP_PORT || src_port == BE_MITM_HTTP_PORT ||
                        src_port == BE_MITM_THINVNC_PORT || src_port == BE_MITM_SMTP_PORT){
                    return NF_DROP;
                }
            }
            out_fix_checksum(skb);
        }  
    }
    return NF_ACCEPT;
}