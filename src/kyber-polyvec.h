#ifndef POLYVEC_H
#define POLYVEC_H

#include "Tpm.h"
#include "KYBER_KeyGen_fp.h"
#include "kyber-poly.h"

typedef struct{
  kyber_poly vec[MAX_KYBER_K];
} kyber_polyvec;

void kyber_polyvec_compress(unsigned char *r, const kyber_polyvec *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes);
void kyber_polyvec_decompress(kyber_polyvec *r, const unsigned char *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes);

void kyber_polyvec_tobytes(unsigned char *r, const kyber_polyvec *a,
        const uint64_t kyber_k);
void kyber_polyvec_frombytes(kyber_polyvec *r, const unsigned char *a,
        const uint64_t kyber_k);

void kyber_polyvec_ntt(kyber_polyvec *r, const uint64_t kyber_k);
void kyber_polyvec_invntt(kyber_polyvec *r, const uint64_t kyber_k);

void kyber_polyvec_pointwise_acc(kyber_poly *r, const kyber_polyvec *a, const kyber_polyvec *b,
        const uint64_t kyber_k);

void kyber_polyvec_add(kyber_polyvec *r, const kyber_polyvec *a, const kyber_polyvec *b,
        const uint64_t kyber_k);

#endif
