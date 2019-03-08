#include "ldaa-polynomial-mix.h"

void ldaa_poly_mul_ntt_1(ldaa_poly_t *this,
        ldaa_poly_ntt_t *a,
        ldaa_poly_t *ba)
{
    ldaa_poly_ntt_t b;
    ldaa_poly_ntt_from_canonical(&b, ba);

    ldaa_poly_ntt_mul(&b, a, &b);
    ldaa_poly_from_ntt(this, &b);
}

void ldaa_poly_from_ntt(ldaa_poly_t *this,
		     ldaa_poly_ntt_t *a)
{
    size_t i;

    for (i = 0; i < LDAA_N; i++) {
        this->coeffs[i] = a->coeffs[i];
    }

    ldaa_poly_invntt(this->coeffs);
}
