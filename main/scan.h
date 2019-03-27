#pragma once

#include <stdint.h>

#define PKT_SUBTYPE_PROBE_REQUEST 0x04

typedef struct {
    void *payload;
    uint32_t length;
    uint32_t seconds;
    uint32_t microseconds;
} sniffer_packet_info_t;

