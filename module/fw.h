#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#define BE_HTTP_PORT (20480)
#define BE_FTP_PORT (5376)
#define BE_THINVNC_PORT (36895)
#define BE_SMTP_PORT (6400) // 25
#define BE_MITM_HTTP_PORT (8195)
#define BE_MITM_FTP_PORT (53760)
#define BE_FTP_DATA_PORT (5120)
#define BE_MITM_SMTP_PORT (64000) // 250
#define BE_MITM_THINVNC_PORT (37151) // 8081
#define BE_FW_IP_HOST1 (50397450) // "10.1.1.3"
#define BE_FW_IP_HOST2 (50462986) // "10.1.2.3"
#define BE_CLIENT_IP (16843018) // "10.1.1.1"
#define BE_SERVER_IP (33685770) // "10.1.2.2"

extern struct kmem_cache* conn_cache;


// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"
#define FW_LOG_DEVICE               "fw_log"
#define CONNS_TABLE_DEVICE          "conns"
#define CONNS_MITM                  "conns_mitm"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define IPV6_VERSION    (6)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define PORT_ABOVE_1023_BE (65283)
#define MAX_RULES		(50)
#define MAX_RULE_NAME   (20)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
    MINOR_FW_LOG   = 2,
    MINOR_CONNS    = 3,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

typedef enum {
	CLOSED = 0,
    LISTEN = 1,
	SYN_RCVD = 2,
	ESTABLISHED = 3,
	FIN_WAIT_1 = 4,
	FIN_WAIT_2 = 5,
    TIME_WAIT_1 = 6,
	CLOSING = 7, 
	SYN_SENT = 8,
	CLOSE_WAIT = 9,
	LAST_ACK = 10,
} tcp_state;

typedef struct {
    __u8 ack;
    __u8 fin;
    __u8 rst;
    __u8 syn;
}tcp_flags;

typedef struct {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;
	__be16	dst_port;
	__be16 mitm_port;
	tcp_state state;
}conn_row_t;

#endif // _FW_H_
