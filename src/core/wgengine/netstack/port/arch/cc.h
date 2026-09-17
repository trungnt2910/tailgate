#pragma once

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif
    uint32_t tailgate_lwip_random(void);
#ifdef __cplusplus
}
#endif

#define LWIP_RAND() tailgate_lwip_random()
#define LWIP_PLATFORM_ASSERT(message) abort()
#define LWIP_NO_UNISTD_H 1
