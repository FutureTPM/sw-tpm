#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "dilithium-params.h"

void dilithium_ntt(uint32_t p[DILITHIUM_N]);
void dilithium_invntt_frominvmont(uint32_t p[DILITHIUM_N]);

#endif
