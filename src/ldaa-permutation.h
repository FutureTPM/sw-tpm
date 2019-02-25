#ifndef LDAA_PERMUTATION_H
#define LDAA_PERMUTATION_H

#include "BaseTypes.h"
#include "ldaa-params.h"
#include "ldaa-polynomial.h"

typedef struct {
    UINT32 v[(2*(1<<LDAA_LOG_W)-1)*LDAA_N];
} ldaa_permutation_t;

void ldaa_permutation_sample_u(ldaa_permutation_t *this);
void ldaa_permutation_embed(ldaa_permutation_t *this, ldaa_poly_t *ps);
void ldaa_permutation_copy(ldaa_permutation_t *this, ldaa_permutation_t *other);

typedef struct {
    UINT32 v[(2*(1<<LDAA_LOG_W)-2)*LDAA_N];
} ldaa_permutation_perm_t;

void ldaa_permutation_perm_sample_u(ldaa_permutation_perm_t *this);

#endif
