#ifndef LDAA_PERMUTATION_H
#define LDAA_PERMUTATION_H

#include "BaseTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial.h"

void ldaa_permutation_sample_u(ldaa_permutation_t *this, uint64_t log_w, uint64_t n);
void ldaa_permutation_embed(ldaa_permutation_t *this, ldaa_poly_t *ps,
        uint64_t log_w, uint64_t n);
void ldaa_permutation_copy(ldaa_permutation_t *this, ldaa_permutation_t *other,
        uint64_t log_w, uint64_t n);

void ldaa_permutation_perm_sample_u(ldaa_permutation_perm_t *this,
        uint64_t log_w, uint64_t n);

#endif
