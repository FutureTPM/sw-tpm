#ifndef LDAA_SIGN_STATE_H
#define LDAA_SIGN_STATE_H

#include "ldaa-params.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial.h"
#include "ldaa-integer-matrix.h"
#include "ldaa-permutation.h"
#include "ldaa-commitment.h"
#include "Tpm.h"

void ldaa_fill_sign_state_tpm(ldaa_sign_state_i_t *sign_state,
		    ldaa_poly_matrix_xt_t *xt,
		    ldaa_poly_t *pe, uint64_t m, uint64_t log_beta, uint64_t log_w,
            uint64_t n, uint64_t q);

void ldaa_tpm_comm_1(ldaa_sign_state_i_t *s,
	   ldaa_poly_t *pbsn,
       ldaa_poly_matrix_ntt_issuer_at_t *atNTT,
       ldaa_commitment1_t *commited,
       size_t seed, uint64_t m, uint64_t log_beta, uint64_t log_w,
       uint64_t n, uint64_t q, uint64_t commit1_len, uint64_t k_comm,
       uint64_t alpha2);

void ldaa_tpm_comm_2(ldaa_sign_state_i_t *s,
        ldaa_commitment2_t *commited, size_t seed,
        uint64_t m, uint64_t log_beta, uint64_t log_w,
        uint64_t n, uint64_t q, uint64_t commit2_len, uint64_t k_comm,
        uint64_t l, uint64_t alpha2);

void ldaa_tpm_comm_3(ldaa_sign_state_i_t *s,
        ldaa_commitment3_t *commited, size_t seed,
        uint64_t m, uint64_t log_beta, uint64_t log_w,
        uint64_t n, uint64_t q, uint64_t commit3_len, uint64_t k_comm,
        uint64_t l, uint64_t alpha2);

void ldaa_fill_sign_state_tpm_fixed(ldaa_sign_state_i_t *sign_state);

#endif
