#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "kyber-params.h"

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[KYBER_N];
} kyber_poly;

void kyber_poly_compress(unsigned char *r, kyber_poly *a, uint64_t kyber_polycompressedbytes);
void kyber_poly_decompress(kyber_poly *r, const unsigned char *a, uint64_t kyber_polycompressedbytes);

void kyber_poly_tobytes(unsigned char *r, kyber_poly *a);
void kyber_poly_frombytes(kyber_poly *r, const unsigned char *a);

void kyber_poly_frommsg(kyber_poly *r, const unsigned char msg[KYBER_SYMBYTES]);
void kyber_poly_tomsg(unsigned char msg[KYBER_SYMBYTES], kyber_poly *r);

void kyber_poly_getnoise(kyber_poly *r,const unsigned char *seed,
        unsigned char nonce, uint64_t kyber_eta);

void kyber_poly_ntt(kyber_poly *r);
void kyber_poly_invntt(kyber_poly *r);

void kyber_poly_add(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);
void kyber_poly_sub(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);

void kyber_poly_frommont(kyber_poly *r);
void kyber_poly_reduce(kyber_poly *r);
void kyber_poly_csubq(kyber_poly *r);

void kyber_poly_basemul(kyber_poly *r, const kyber_poly *a, const kyber_poly *b);

#endif
