#ifndef POLYVEC_H
#define POLYVEC_H

#include "Tpm.h"
#include "KYBER_KeyGen_fp.h"
#include "kyber-poly.h"

typedef struct{
  poly vec[MAX_KYBER_K];
} polyvec;

void polyvec_compress(unsigned char *r, const polyvec *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes);
void polyvec_decompress(polyvec *r, const unsigned char *a,
        const uint64_t kyber_k, const uint64_t kyber_polyveccompressedbytes);

void polyvec_tobytes(unsigned char *r, const polyvec *a,
        const uint64_t kyber_k);
void polyvec_frombytes(polyvec *r, const unsigned char *a,
        const uint64_t kyber_k);

void polyvec_ntt(polyvec *r, const uint64_t kyber_k);
void polyvec_invntt(polyvec *r, const uint64_t kyber_k);

void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b,
        const uint64_t kyber_k);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b,
        const uint64_t kyber_k);

#endif
