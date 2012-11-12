/*
 * This header just simulate some OCK log macros to minimize effort to reuse
 * code
 */

#ifndef LOG_H
#define LOG_H

#include <stdlib.h>
#include <stdio.h>

#define OCK_LOG_DEBUG(fmt, ...)                                             \
    do {                                                                    \
        if (getenv("ICSF_DEBUG")) {                                         \
            fprintf(stderr, "----------------------------------------"      \
                            "---------------------------------------\n"     \
                            "%s() @ %s:%d\n" fmt, __FUNCTION__, __FILE__,   \
                            __LINE__, ##__VA_ARGS__);                       \
        }                                                                   \
    } while (0) 

#define OCK_LOG_ERR(err)                                                    \
    do {                                                                    \
        if (getenv("ICSF_DEBUG")) {                                         \
            OCK_LOG_DEBUG("Error: " #err "\n");                             \
        } else {                                                            \
            fprintf(stderr, "Error: " #err "\n");                           \
        }                                                                   \
    } while (0)

#endif
