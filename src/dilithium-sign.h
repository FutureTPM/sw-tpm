#ifndef DILITHIUM_SIGN_H
#define DILITHIUM_SIGN_H

#include "dilithium-polyvec.h"

void dilithium_expand_mat(dilithium_polyvecl *mat,
        const unsigned char rho[DILITHIUM_SEEDBYTES],
        uint64_t dilithium_k, uint64_t dilithium_l);

#endif
