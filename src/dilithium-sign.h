#ifndef DILITHIUM_SIGN_H
#define DILITHIUM_SIGN_H

#include "dilithium-polyvec.h"

void dilithium_expand_mat(dilithium_polyvecl *mat,
        const unsigned char rho[DILITHIUM_SEEDBYTES],
        uint64_t dilithium_k, uint64_t dilithium_l);

void dilithium_challenge(dilithium_poly *c,
               const unsigned char mu[DILITHIUM_CRHBYTES],
               const dilithium_polyveck *w1,
               uint64_t dilithium_k,
               uint64_t dilithium_polw1_size_packed);
#endif
