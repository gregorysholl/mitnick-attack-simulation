#ifndef __SNIFF_H__
#define __SNIFF_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

void sniff_open_session();

void sniff_add_filter(const char *);

void sniff_start(int, pcap_handler);

#endif