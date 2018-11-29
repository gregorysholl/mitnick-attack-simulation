#ifndef __FLOOD_H__
#define __FLOOD_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnet.h>

void flood_server(libnet_t *);

void unflood_server(libnet_t *);

#endif