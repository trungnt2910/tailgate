#pragma once

#include "lwip/arch.h"

#include <stdint.h>

typedef struct ip4_addr
{
    uint32_t addr;
} ip4_addr_t;

typedef struct ip_addr
{
    uint32_t addr;
} ip_addr_t;

#define IPADDR_TYPE_V4 0

static inline void ip_addr_set_ip4_u32(ip_addr_t* address, uint32_t value)
{
    address->addr = value;
}
