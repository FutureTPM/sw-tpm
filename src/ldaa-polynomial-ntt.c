#include "ldaa-polynomial-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-uniform-int.h"
#include <stddef.h>

void ldaa_poly_ntt_mul(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b,
        uint64_t n)
{
    size_t i;
    UINT32 (*reduce)(UINT64 x);

    switch (n) {
        case LDAA_WEAK_N:
            reduce = ldaa_reduce_3329;
            break;
        case LDAA_MEDIUM_N:
            reduce = ldaa_reduce_8380417;
            break;
        case LDAA_HIGH_N:
            reduce = ldaa_reduce_8380417;
            break;
        default:
            break;
    }

    for (i = 0; i < n; i++) {
        this->coeffs[i] = reduce((UINT64)a->coeffs[i] * b->coeffs[i]);
    }
}

void ldaa_poly_ntt_add(ldaa_poly_ntt_t *this,
        ldaa_poly_ntt_t *a,
        ldaa_poly_ntt_t *b,
        uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        this->coeffs[i] = a->coeffs[i] + b->coeffs[i];
        if (this->coeffs[i] >= q) {
            this->coeffs[i] -= q;
        }
    }
}

void ldaa_poly_ntt_from_canonical(ldaa_poly_ntt_t *this,
        ldaa_poly_t *a,
        uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        this->coeffs[i] = a->coeffs[i];
    }

    ldaa_poly_ntt(this->coeffs, n, q);
}

void ldaa_poly_ntt_sample_u(ldaa_poly_ntt_t *out, DRBG_STATE *state, uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out->coeffs[i] = ldaa_uniform_int_sample(0, q, state);
    }
}
