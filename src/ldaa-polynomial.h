#ifndef LDAA_POLYNOMIAL_H
#define LDAA_POLYNOMIAL_H
#include "BaseTypes.h"
#include "ldaa-params.h"

typedef struct {
  UINT32 coeffs[LDAA_N];
} ldaa_poly_t;

void ldaa_poly_sample_z(ldaa_poly_t *this);
void ldaa_poly_add(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b);
void ldaa_poly_mul(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b);
void ldaa_poly_ntt(UINT32 *xs);
void ldaa_poly_invntt(UINT32 *xs);
void ldaa_poly_from_hash(
        // OUT: Resulting polynomial from the Hash
        ldaa_poly_t *out,
        // IN: Hash digest to convert
        BYTE *digest
        );
UINT32 ldaa_reduce(UINT64 x);

#endif
