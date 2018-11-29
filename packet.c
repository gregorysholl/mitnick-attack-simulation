#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>

#include <netinet/in.h>
#include <inttypes.h>

#include "packet.h"

libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;

u_int32_t get_ip_addr(libnet_t *l, char string_addr[16]) {
    u_int32_t ip_addr = libnet_name2addr4(l, string_addr, LIBNET_DONT_RESOLVE);
    if ((int) ip_addr == -1) {
        fprintf(stderr, "Could not convert IP address: %s\n", string_addr);
        libnet_destroy(l);
        exit(1);
    }
    return ip_addr;
}

u_int32_t get_xterminal_ip_addr(libnet_t *l) {
    return get_ip_addr(l, XTERMINAL_IP);
}

u_int32_t get_server_ip_addr(libnet_t *l) {
    return get_ip_addr(l, SERVER_IP);
}

void send_packet_payload(libnet_t *l, uint32_t sequence_number, uint32_t acknowledgement_number,
                         uint8_t control_flags,
                         u_int32_t dst_addr, u_int32_t dst_port,
                         u_int32_t src_addr, u_int32_t src_port,
                         char* payload, uint32_t payload_length) {

    tcp_tag = libnet_build_tcp(
        src_port, //src port
        dst_port, //dst port
        sequence_number, //sequence number
        acknowledgement_number, //ack number
        control_flags, //control flags
        libnet_get_prand(LIBNET_PRu16), //window size
        0, //checksum
        0, //urgent pointer ?
        LIBNET_TCP_H + payload_length, //packet length
        (u_int8_t*) payload, //payload
        payload_length, //payload length
        l, //libnet context
        tcp_tag //tag
    );
    if (tcp_tag < 0) {
        fprintf(stderr, "Could not build TCP header.\n");
        libnet_destroy(l);
        exit(1);
    }

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payload_length, //packet length
        0, //type of service
        libnet_get_prand(LIBNET_PRu16), //sequence number
        0, //fragmentation flags
        64, //ttl
        IPPROTO_TCP, //protocol
        0, //checksum
        src_addr, //src ip address
        dst_addr, //dst ip address
        NULL, //payload
        0, //payload length
        l, //libnet context
        ip_tag //tag
    );
    if (ip_tag < 0) {
        fprintf(stderr, "Could not build IP header.\n");
        libnet_destroy(l);
        exit(1);
    }

    int write = libnet_write(l);
    if (write == -1) {
        fprintf(stderr, "Could not send packet.\n");
        fprintf(stderr, "Error: %s", libnet_geterror(l));
    }
}