#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

pcap_t *handler;

bpf_u_int32 mask;
bpf_u_int32 net;

void sniff_open_session() {

    char errbuf[PCAP_ERRBUF_SIZE];

    //setup device
    char *device = pcap_lookupdev(errbuf);
    if (!device) {
        fprintf(stderr, "Could not find default device.\n");
        fprintf(stderr, "Error: %s", errbuf);
        exit(1);
    }

    //obtain network information
    if (pcap_lookupnet(device, &net, &mask, errbuf) < 0) {
        fprintf(stderr, "Could not obtain information about the network.\n");
        fprintf(stderr, "Error: %s", errbuf);
        exit(1);
    }

    fprintf(stdout, "Device: %s\n", device);

    //open sniffing session
    handler = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handler) {
        fprintf(stderr, "Could not open sniffing session.\n");
        fprintf(stderr, "Error: %s", errbuf);
        exit(1);
    }
}

void sniff_add_filter(const char *expression) {
    if (!handler || !expression) {
        fprintf(stderr, "Could not add filter to sniffing session.\n");
        exit(1);
    }

    fprintf(stdout, "Filter expression: %s\n", expression);

    //filter traffic
    struct bpf_program fp;
    if (pcap_compile(handler, &fp, expression, 0, net) < 0) {
        fprintf(stderr, "Could not compile filter expression.\n");
        fprintf(stderr, "Error: %s", pcap_geterr(handler));
        pcap_close(handler);
        exit(1);
    }

    if (pcap_setfilter(handler, &fp) < 0) {
        fprintf(stderr, "Could not set filter expression.\n");
        fprintf(stderr, "Error: %s", pcap_geterr(handler));
        pcap_close(handler);
        exit(1);
    }
}

void sniff_start(int count, pcap_handler callback) {
    if (!handler) {
        fprintf(stderr, "Cannot start unopened sniffing session.\n");
        exit(1);
    }

    fprintf(stdout, "Preparing to sniff %d packets...\n", count);

    pcap_loop(handler, count, callback, NULL);

    pcap_close(handler);

    handler = NULL;
}