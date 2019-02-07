#ifndef LDAA_SIGN_STATE_H
#define LDAA_SIGN_STATE_H

#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-integer-matrix.h"
#include "ldaa-permutation.h"
#include "ldaa-commitment.h"

typedef struct {
    ldaa_integer_matrix_t x[LDAA_M*LDAA_LOG_BETA];
    ldaa_integer_matrix_t r[LDAA_M*LDAA_LOG_BETA];
    ldaa_integer_matrix_t v[LDAA_M*LDAA_LOG_BETA];

    ldaa_integer_matrix_t e[LDAA_LOG_BETA];
    ldaa_integer_matrix_t re[LDAA_LOG_BETA];
    ldaa_integer_matrix_t ve[LDAA_LOG_BETA];

    ldaa_permutation_t phi[LDAA_LOG_BETA];
    ldaa_permutation_t varphi[LDAA_LOG_BETA];

    ldaa_poly_matrix_R_t R1, R2, R3;
} ldaa_sign_state_i_t;


void ldaa_fill_sign_state_tpm(ldaa_sign_state_i_t *sign_state,
		    ldaa_poly_matrix_xt_t *xt,
		    ldaa_poly_t *pe);

void ldaa_tpm_comm_1(ldaa_sign_state_i_t *s,
	   ldaa_poly_t *pbsn,
       ldaa_poly_matrix_ntt_issuer_at_t *atNTT,
       ldaa_commitment1_t *commited,
       ldaa_poly_matrix_ntt_B_t *BNTT);

void ldaa_tpm_comm_2(ldaa_sign_state_i_t *s,
        ldaa_commitment2_t *commited,
        ldaa_poly_matrix_ntt_B2_t *BNTT);
#endif
