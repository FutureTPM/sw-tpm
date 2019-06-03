#include "ldaa-polynomial-mix.h"
#include <stddef.h>

void ldaa_poly_mul_ntt_1(ldaa_poly_t *this,
        ldaa_poly_ntt_t *a,
        ldaa_poly_t *ba, uint64_t n, uint64_t q)
{
    ldaa_poly_ntt_t b;
    ldaa_poly_ntt_from_canonical(&b, ba, n, q);

    ldaa_poly_ntt_mul(&b, a, &b, n);
    ldaa_poly_from_ntt(this, &b, n, q);
}

void ldaa_poly_from_ntt(ldaa_poly_t *this,
		     ldaa_poly_ntt_t *a, uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        this->coeffs[i] = a->coeffs[i];
    }

    ldaa_poly_invntt(this->coeffs, n, q);
}
