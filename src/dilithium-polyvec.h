#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  dilithium_poly vec[5]; // Max L
} dilithium_polyvecl;

void dilithium_polyvecl_freeze(dilithium_polyvecl *v, uint64_t dilithium_l);

void dilithium_polyvecl_add(dilithium_polyvecl *w, const dilithium_polyvecl *u, const dilithium_polyvecl *v, uint64_t dilithium_l);

void dilithium_polyvecl_ntt(dilithium_polyvecl *v, uint64_t dilithium_l);
void dilithium_polyvecl_pointwise_acc_invmontgomery(dilithium_poly *w,
                                          const dilithium_polyvecl *u,
                                          const dilithium_polyvecl *v,
                                          uint64_t dilithium_l);

int dilithium_polyvecl_chknorm(const dilithium_polyvecl *v, uint32_t B, uint64_t dilithium_l);



/* Vectors of polynomials of length K */
typedef struct {
  dilithium_poly vec[6]; // Max K
} dilithium_polyveck;

void dilithium_polyveck_reduce(dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_csubq(dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_freeze(dilithium_polyveck *v, uint64_t dilithium_k);

void dilithium_polyveck_add(dilithium_polyveck *w, const dilithium_polyveck *u, const dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_sub(dilithium_polyveck *w, const dilithium_polyveck *u, const dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_shiftl(dilithium_polyveck *v, unsigned int k, uint64_t dilithium_k);

void dilithium_polyveck_ntt(dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_invntt_montgomery(dilithium_polyveck *v, uint64_t dilithium_k);

int dilithium_polyveck_chknorm(const dilithium_polyveck *v, uint32_t B, uint64_t dilithium_k);

void dilithium_polyveck_power2round(dilithium_polyveck *v1, dilithium_polyveck *v0, const dilithium_polyveck *v, uint64_t dilithium_k);
void dilithium_polyveck_decompose(dilithium_polyveck *v1, dilithium_polyveck *v0, const dilithium_polyveck *v, uint64_t dilithium_k);
unsigned int dilithium_polyveck_make_hint(dilithium_polyveck *h,
                                const dilithium_polyveck *u,
                                const dilithium_polyveck *v,
                                uint64_t dilithium_k);
void dilithium_polyveck_use_hint(dilithium_polyveck *w, const dilithium_polyveck *v, const dilithium_polyveck *h, uint64_t dilithium_k);

#endif
