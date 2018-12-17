#ifndef NTT_H
#define NTT_H

#include <stdint.h>

void kyber_ntt(uint16_t* poly);
void kyber_invntt(uint16_t* poly);

#endif
