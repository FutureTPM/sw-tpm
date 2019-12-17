#ifndef NTTRU_NTT_H
#define NTTRU_NTT_H

#include <stdint.h>

extern int16_t nttru_zetas[256];
extern int16_t nttru_zetas_inv[256];
extern int16_t nttru_zetas_exp[1084];
extern int16_t nttru_zetas_inv_exp[1084];

void nttru_init_ntt(void);
void nttru_ntt(int16_t b[768], const int16_t a[768]);
void nttru_invntt(int16_t b[768], const int16_t a[768]);
void nttru_ntt_pack(int16_t b[768], const int16_t a[768]);
void nttru_ntt_unpack(int16_t b[768], const int16_t a[768]);
void nttru_basemul(int16_t c[3],
                   const int16_t a[3],
                   const int16_t b[3],
                   int16_t zeta);
int nttru_baseinv(int16_t b[3], const int16_t a[3], int16_t zeta);

#endif
