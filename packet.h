#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>
#include <netinet/in.h>
#include <inttypes.h>

#define XTERMINAL_IP "172.16.17.4"
#define SERVER_IP "172.16.17.3"
#define MY_IP "172.16.17.2"

#define RLOGIN_PORT "513"
#define RSH_PORT "514"

u_int32_t get_ip_addr(libnet_t *, char[]);

u_int32_t get_xterminal_ip_addr(libnet_t *);

u_int32_t get_server_ip_addr(libnet_t *);

void send_packet_payload(libnet_t*, uint32_t, uint32_t, uint8_t, u_int32_t, u_int32_t, u_int32_t, u_int32_t, char*, uint32_t);

#endif