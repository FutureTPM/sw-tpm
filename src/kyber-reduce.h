#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

int16_t kyber_montgomery_reduce(int32_t a);

int16_t kyber_barrett_reduce(int16_t a);

int16_t kyber_csubq(int16_t a);

#endif
