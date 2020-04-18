#ifndef FIREWALL_IMPL_H
#define FIREWALL_IMPL_H

#include <linux/netfilter.h>
#include "fw.h"


int firewall(log_row_t** dynamic_log, log_row_t* single_entry_log, size_t* log_count,
                      size_t* total_alloc_size_log,
                      rule_t rule_table[MAX_RULES], size_t rule_count,
                      const struct net_device *in,
                      struct sk_buff *skb);

unsigned int fix_packet_fields(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff*));
#endif