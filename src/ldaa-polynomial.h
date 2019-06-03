#ifndef LDAA_POLYNOMIAL_H
#define LDAA_POLYNOMIAL_H
#include "BaseTypes.h"
#include "Tpm.h"
#include "ldaa-params.h"

void ldaa_poly_sample_z(ldaa_poly_t *this, uint64_t n, uint64_t s, uint64_t q);
void ldaa_poly_sample_u(ldaa_poly_t *out, DRBG_STATE *state, uint64_t n, uint64_t q);
void ldaa_poly_add(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b,
        uint64_t n, uint64_t q);
void ldaa_poly_mul(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b,
        uint64_t n, uint64_t q);
void ldaa_poly_ntt(UINT32 *xs, uint64_t n, uint64_t q);
void ldaa_poly_invntt(UINT32 *xs, uint64_t n, uint64_t q);
void ldaa_poly_from_hash(
        // OUT: Resulting polynomial from the Hash
        ldaa_poly_t *out,
        // IN: Hash digest to convert
        BYTE *digest,
        uint64_t n,
        uint64_t q
        );
UINT32 ldaa_reduce_8380417(UINT64 x);
UINT32 ldaa_reduce_3329(UINT64 x);

#endif
