#ifndef _RULETABLE_H_
#define _RULETABLE_H_
#include "fw.h"

ssize_t load_rule_table(rule_t rule_table[MAX_RULES], size_t* rules_count, const char *buf, size_t count);

int print_rule_table(rule_t rule_table[MAX_RULES], size_t rules_count, char *buf, size_t count);

#endif