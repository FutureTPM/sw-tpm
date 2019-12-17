#ifndef NTTRU_POLY_H
#define NTTRU_POLY_H

#include <stdint.h>
#include "nttru-params.h"

#define NTTRU_POLY_PACKED_UNIFORM_BYTES (NTTRU_LOGQ*NTTRU_N/8)
#define NTTRU_POLY_PACKED_SHORT_BYTES (NTTRU_LOGQ*NTTRU_N/8)

typedef struct {
  int16_t coeffs[NTTRU_N];
} nttru_poly __attribute__((aligned(32)));

void nttru_poly_reduce(nttru_poly *a);
void nttru_poly_freeze(nttru_poly *a);

void nttru_poly_add(nttru_poly *c, const nttru_poly *a, const nttru_poly *b);
void nttru_poly_triple(nttru_poly *b, const nttru_poly *a);

void nttru_poly_ntt(nttru_poly *b, const nttru_poly *a);
void nttru_poly_invntt(nttru_poly *b, const nttru_poly *a);
void nttru_poly_basemul(nttru_poly *c, const nttru_poly *a, const nttru_poly *b);
int  nttru_poly_baseinv(nttru_poly *b, const nttru_poly *a);

void nttru_poly_uniform(nttru_poly *a, const unsigned char *buf);
void nttru_poly_short(nttru_poly *a, const unsigned char *buf);

void nttru_poly_crepmod3(nttru_poly *b, const nttru_poly *a);

void nttru_poly_pack_uniform(unsigned char *buf, const nttru_poly *a);
void nttru_poly_unpack_uniform(nttru_poly *a, const unsigned char *buf);
void nttru_poly_pack_short(unsigned char *buf, const nttru_poly *a);
void nttru_poly_unpack_short(nttru_poly *a, const unsigned char *buf);

#endif
