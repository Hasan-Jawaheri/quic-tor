#ifndef __QUICSOCK_TYPES_H__
#define __QUICSOCK_TYPES_H__

#include <stdint.h>

// Defined in quicsock_internal.h
struct quicsock_internal_s;
typedef struct quicsock_internal_s* quicsock_t;

// User stream ID.
typedef uint64_t quicsock_stream_id_t;

#endif /* __QUICSOCK_TYPES_H__ */
