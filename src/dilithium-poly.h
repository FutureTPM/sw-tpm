#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "dilithium-params.h"

typedef struct {
  uint32_t coeffs[DILITHIUM_N];
} dilithium_poly __attribute__((aligned(32)));

void dilithium_poly_reduce(dilithium_poly *a);
void dilithium_poly_csubq(dilithium_poly *a);
void dilithium_poly_freeze(dilithium_poly *a);

void dilithium_poly_add(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b);
void dilithium_poly_sub(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b);
void dilithium_poly_neg(dilithium_poly *a);
void dilithium_poly_shiftl(dilithium_poly *a);

void dilithium_poly_ntt(dilithium_poly *a);
void dilithium_poly_invntt_montgomery(dilithium_poly *a);
void dilithium_poly_pointwise_invmontgomery(dilithium_poly *c, const dilithium_poly *a, const dilithium_poly *b);

void dilithium_poly_power2round(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a);
void dilithium_poly_decompose(dilithium_poly *a1, dilithium_poly *a0, const dilithium_poly *a);
unsigned int dilithium_poly_make_hint(dilithium_poly *h,
        const dilithium_poly *a0, const dilithium_poly *a1);
void dilithium_poly_use_hint(dilithium_poly *a, const dilithium_poly *b, const dilithium_poly *h);

int  dilithium_poly_chknorm(const dilithium_poly *a, uint32_t B);
void dilithium_poly_uniform(dilithium_poly *a,
        const unsigned char seed[DILITHIUM_SEEDBYTES],
        uint16_t nonce);
void dilithium_poly_uniform_eta(dilithium_poly *a,
                      const unsigned char seed[DILITHIUM_SEEDBYTES],
                      uint16_t nonce, uint64_t dilithium_eta,
                      uint64_t dilithium_setabits);
void dilithium_poly_uniform_gamma1m1(dilithium_poly *a,
                           const unsigned char seed[DILITHIUM_CRHBYTES],
                           uint16_t nonce);

void dilithium_polyeta_pack(unsigned char *r, const dilithium_poly *a, uint64_t dilithium_eta);
void dilithium_polyeta_unpack(dilithium_poly *r, const unsigned char *a, uint64_t dilithium_eta);

void dilithium_polyt1_pack(unsigned char *r, const dilithium_poly *a);
void dilithium_polyt1_unpack(dilithium_poly *r, const unsigned char *a);

void dilithium_polyt0_pack(unsigned char *r, const dilithium_poly *a);
void dilithium_polyt0_unpack(dilithium_poly *r, const unsigned char *a);

void dilithium_polyz_pack(unsigned char *r, const dilithium_poly *a);
void dilithium_polyz_unpack(dilithium_poly *r, const unsigned char *a);

void dilithium_polyw1_pack(unsigned char *r, const dilithium_poly *a);
#endif
