#pragma once

// Tailgate supplies packet devices and scheduling; lwIP must not own host sockets or threads.
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_NETIF_API 0
#define LWIP_TCP 1
#define LWIP_UDP 0
#define LWIP_RAW 1
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_IGMP 0
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
// Reassembly metadata contains a pointer and does not fit an IPv6 fragment header on 64-bit.
#define IPV6_FRAG_COPYHEADER 1
#define IP_FORWARD 0
#define LWIP_IPV6_FORWARD 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 0

// Bound each stack's storage while allowing several independently backpressured transfers.
#define MEM_ALIGNMENT 8
#define MEM_SIZE (8U * 1024U * 1024U)
#define MEMP_NUM_TCP_PCB 128
#define MEMP_NUM_TCP_PCB_LISTEN 8
#define MEMP_NUM_RAW_PCB 5
#define MEMP_NUM_TCP_SEG 4096
#define MEMP_NUM_PBUF 1024
#define PBUF_POOL_SIZE 512
#define TCP_MSS 1200
#define TCP_WND (64U * TCP_MSS)
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define TCP_SND_BUF (64U * TCP_MSS)
#define TCP_SND_QUEUELEN 256
#define TCP_LISTEN_BACKLOG 1
#define LWIP_TCP_PCB_NUM_EXT_ARGS 1
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_TCP_SACK_OUT 1

// Pool occupancy exposes pending reassembly without duplicating upstream queues.
// Other statistics are unnecessary for deciding whether cyclic timers need a wakeup.
#define LWIP_STATS 1
#define MEMP_STATS 1
#define LINK_STATS 0
#define IP_STATS 0
#define IPFRAG_STATS 0
#define ICMP_STATS 0
#define TCP_STATS 0
#define MEM_STATS 0
#define IP6_STATS 0
#define ICMP6_STATS 0
#define IP6_FRAG_STATS 0
#define ND6_STATS 0

#define LWIP_HOOK_FILENAME "Hooks.h"
#define LWIP_HOOK_TCP_ISN(local, local_port, remote, remote_port)                                  \
    tailgate_lwip_tcp_isn(local, local_port, remote, remote_port)
