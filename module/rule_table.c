#include "rule_table.h"
#include <linux/string.h>

#define RULE_LINE_ELEMENTS 13
#define MAX_LINE_CHARS 100

/*
* Loads the table passed from user space into the rule table
*/
ssize_t load_rule_table(rule_t rule_table[MAX_RULES], size_t* rules_count, const char *buf, size_t count){
    int word_in_line, res_value;
    char* tok, *end, *str_table;
    __u8 direction; 
    __be32 src_ip; __be32 src_prefix_mask; __u8 src_prefix_size;						
	__be32 dst_ip; __be32 dst_prefix_mask;  __u8 dst_prefix_size; 
	__be16 src_port;  __be16 dst_port; 			
	__u8	protocol; 		
	__u8	ack; 				
	__u8	action;   			
    
    if (count < 2){
        return -1;
    }
    str_table = kmalloc((sizeof(char) * count) + sizeof(char), GFP_KERNEL);
    if (str_table == NULL){
        return -1;
    }

    memcpy(str_table, buf, count);
    *(str_table+count) = '\0';
    *rules_count  = 0;
    tok = str_table; end = str_table;
    
    while (1){
        if (*rules_count == (MAX_RULES + 1)){
            printk(KERN_INFO "Error: number of line rules exceeds 50");
            kfree(str_table);
            return -1;
        }
       for (word_in_line = 0 ; word_in_line < RULE_LINE_ELEMENTS; word_in_line++){
            tok = strsep(&end, " ");
            if (tok == NULL){
                if (*rules_count > 0 && word_in_line == 0){
                    kfree(str_table);
                    return count;
                }
                else if ((word_in_line + 1) != RULE_LINE_ELEMENTS){
                    printk(KERN_INFO "Error: line %d ended too soon (only %d words)", *rules_count, word_in_line);
                    kfree(str_table);
                    return -1;
                }
                else{
                    printk(KERN_INFO "Error: invalid location");
                    kfree(str_table);
                    return -1; 
                }
                
            }
            switch (word_in_line){ 
                case 0:
                    if (strlen(tok) > (MAX_RULE_NAME - 1) ){
                        printk(KERN_INFO "Error: rule name %s is over the limit", tok);
                        kfree(str_table);
                        return -1;
                    }
                    else {
                        strncpy(rule_table[*rules_count].rule_name, tok, MAX_RULE_NAME);
                        
                    }
                    break;
                    
                case 1:
                    res_value = kstrtou8(tok, 10, &direction);
                    if (res_value == -EINVAL || direction < 0 || direction > 3){
                        printk(KERN_INFO "Error: invalid direction value: %d", direction);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    else {
                        rule_table[*rules_count].direction = direction;
                    }
                    break;
                    
                case 2:
                    res_value = kstrtou32(tok, 10, &src_ip);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid src_ip value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    src_ip = cpu_to_be32(src_ip);
                    rule_table[*rules_count].src_ip = src_ip;
                    break;
                    
                case 3:
                    res_value = kstrtou32(tok, 10, &src_prefix_mask);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid src_prefix_mask value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    src_prefix_mask = cpu_to_be32(src_prefix_mask);
                    rule_table[*rules_count].src_prefix_mask = src_prefix_mask;
                    break;
                    
                case 4:
                    res_value = kstrtou8(tok, 10, &src_prefix_size);
                    if (res_value == -EINVAL || src_prefix_size < 0 || src_prefix_size > 32){
                        printk(KERN_INFO "Error: got invalid src_prefix_size value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    rule_table[*rules_count].src_prefix_size = src_prefix_size;
                    break; 						
	
                    
                case 5:
                    res_value = kstrtou32(tok, 10, &dst_ip);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid dst_ip value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    dst_ip = cpu_to_be32(dst_ip);  
                    rule_table[*rules_count].dst_ip = dst_ip;
                    break;
                    
                case 6:
                    res_value = kstrtou32(tok, 10, &dst_prefix_mask);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid dst_prefix_mask value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    dst_prefix_mask = cpu_to_be32(dst_prefix_mask);
                    rule_table[*rules_count].dst_prefix_mask = dst_prefix_mask;
                    break;
                    
                case 7:
                    res_value = kstrtou8(tok, 10, &dst_prefix_size);
                    if (res_value == -EINVAL || dst_prefix_size < 0 || dst_prefix_size > 32){
                        printk(KERN_INFO "Error: got invalid dst_prefix_size value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    rule_table[*rules_count].dst_prefix_size = dst_prefix_size;
                    break;
                    
                case 8:
                    res_value = kstrtou16(tok, 10, &src_port);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid src_port value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    src_port = cpu_to_be16(src_port);
                    rule_table[*rules_count].src_port = src_port;
                    break;									  
                    
                case 9:
                    res_value = kstrtou16(tok, 10, &dst_port);
                    if (res_value == -EINVAL){
                        printk(KERN_INFO "Error: got invalid dst_port value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    dst_port = cpu_to_be16(dst_port);
                    rule_table[*rules_count].dst_port = dst_port;
                    break;
                    
                case 10:
                    res_value = kstrtou8(tok, 10, &protocol);
                    if (res_value == -EINVAL || (protocol != PROT_ICMP
                                                && protocol != PROT_TCP
                                                 && protocol != PROT_UDP
                                                 && protocol != PROT_OTHER
                                                 && protocol != PROT_ANY
                                                )){
                        printk(KERN_INFO "Error: got invalid protocol value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    rule_table[*rules_count].protocol = protocol;
                    break;
                    
                case 11:
                    res_value = kstrtou8(tok, 10, &ack);
                    if (res_value == -EINVAL || ( ack != ACK_NO
                                                 && ack != ACK_YES
                                                 && ack!= ACK_ANY
                                                )){
                        printk(KERN_INFO "Error: got invalid ack value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    rule_table[*rules_count].ack = ack;
                    break;
                    
                case 12:
            
                    res_value = kstrtou8(tok, 10, &action);
                    if (res_value == -EINVAL || (action != NF_DROP && action != NF_ACCEPT)){
                        printk(KERN_INFO "Error: got invalid action value: %s", tok);
                        kfree(str_table);
                        return -EINVAL;
                    }
                    rule_table[*rules_count].action = action;
                    break;
            }
            tok=end;
        } 
        (*rules_count)++;
    }
    return -1; // should not get here
}

/*
* Sends the rule table raw data to the user-space
*/
int print_rule_table(rule_t rule_table[MAX_RULES], size_t rules_count, char *buf, size_t count){
    int i, bytes_written;
    char *all_lines = kcalloc(MAX_RULES*MAX_LINE_CHARS+1, sizeof(char), GFP_KERNEL); // this can also be done statically
    char line[MAX_LINE_CHARS+1] = {0}; // each log line is bounded by name (20 chars), and certain numbers (by my calculation it cannot be more than 100 chars)
    for (i=0 ; i < rules_count; i++){ 
        scnprintf(line, MAX_LINE_CHARS, "%s %u %u %u %u %u %u %u %u %u %u\n", 
                                        rule_table[i].rule_name,
                                        rule_table[i].direction,
                                        rule_table[i].src_ip,
                                        rule_table[i].src_prefix_size, 
                                        rule_table[i].dst_ip,
                                        rule_table[i].dst_prefix_size,
                                        rule_table[i].src_port,
                                        rule_table[i].dst_port,
                                        rule_table[i].protocol,
                                        rule_table[i].ack,
                                        rule_table[i].action
                            );
        strncat(all_lines,line, MAX_LINE_CHARS);
    }
    bytes_written = scnprintf(buf, PAGE_SIZE, "%s", all_lines);
    kfree(all_lines);
    return bytes_written;
}