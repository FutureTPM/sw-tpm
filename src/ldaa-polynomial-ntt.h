#ifndef LDAA_POLYNOMIAL_NTT_H
#define LDAA_POLYNOMIAL_NTT_H
#include "BaseTypes.h"
#include "ldaa-params.h"
#include "TpmTypes.h"
#include "Tpm.h"

void ldaa_poly_ntt_from_canonical(ldaa_poly_ntt_t *this, ldaa_poly_t *a,
        uint64_t n, uint64_t q);
void ldaa_poly_ntt_sample_u(ldaa_poly_ntt_t *out, DRBG_STATE *state,
        uint64_t n, uint64_t q);
void ldaa_poly_ntt_mul(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b,
        uint64_t n);
void ldaa_poly_ntt_add(ldaa_poly_ntt_t *this,
		ldaa_poly_ntt_t *a,
		ldaa_poly_ntt_t *b,
        uint64_t n, uint64_t q);

#endif

