#ifndef NTT_H
#define NTT_H

#include <stdint.h>

extern int16_t kyber_zetas[128];
extern int16_t kyber_zetasinv[128];

void kyber_ntt(int16_t r[256]);
void kyber_invntt(int16_t r[256]);
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
