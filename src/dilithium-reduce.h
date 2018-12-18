#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

#define DILITHIUM_MONT 4193792U // 2^32 % Q
#define DILITHIUM_QINV 4236238847U // -q^(-1) mod 2^32

/* a <= Q*2^32 => r < 2*Q */
uint32_t dilithium_montgomery_reduce(uint64_t a);

/* r < 2*Q */
uint32_t dilithium_reduce32(uint32_t a);

/* a < 2*Q => r < Q */
uint32_t dilithium_csubq(uint32_t a);

/* r < Q */
uint32_t dilithium_freeze(uint32_t a);

#endif
