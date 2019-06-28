#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-params.h"

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed, uint64_t commit1_len,
            uint64_t n, uint64_t k_comm, uint64_t q)
{
    size_t i, j, k, l;
    UINT32 prod = 0;
    TPM2B_SEED tpm2b_seed;
    ldaa_poly_ntt_t a_ntt;
    DRBG_STATE rand;
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

    MemoryCopy(tpm2b_seed.b.buffer, &seed, sizeof(size_t));
    tpm2b_seed.b.size = sizeof(size_t);
    TPM2B_STRING(HOST_B_NTT_GENERATION, "Host B NTT Generation");
    DRBG_InstantiateSeeded(&rand, &tpm2b_seed.b,
            HOST_B_NTT_GENERATION, NULL, NULL);

    for (i = 0; i < commit1_len + 1; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < k_comm; k++) {
                ldaa_poly_ntt_sample_u(&a_ntt, &rand, n, q);
                for (l = 0; l < n; l++) {
                    prod = reduce((UINT64)a_ntt.coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] += prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed, uint64_t commit2_len,
            uint64_t n, uint64_t k_comm, uint64_t q)
{
    size_t i, j, k, l;
    UINT32 prod = 0;
    TPM2B_SEED tpm2b_seed;
    ldaa_poly_ntt_t a_ntt;
    DRBG_STATE rand;
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

    MemoryCopy(tpm2b_seed.b.buffer, &seed, sizeof(size_t));
    tpm2b_seed.b.size = sizeof(size_t);
    TPM2B_STRING(HOST_B_NTT_GENERATION, "Host B NTT Generation");
    DRBG_InstantiateSeeded(&rand, &tpm2b_seed.b,
            HOST_B_NTT_GENERATION, NULL, NULL);

    for (i = 0; i < commit2_len + 1; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < k_comm; k++) {
                ldaa_poly_ntt_sample_u(&a_ntt, &rand, n, q);
                for (l = 0; l < n; l++) {
                    prod = reduce((UINT64)a_ntt.coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] = this->coeffs[i * 1 + j].coeffs[l] + prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_commit_t *a, uint64_t n, uint64_t k_comm,
               uint64_t q)
{
    size_t i, j;
    for (i = 0; i < k_comm; i++) {
        for (j = 0; j < n; j++) {
            if (j == 0) {
                this->coeffs[i].coeffs[j] = a->coeffs[i];
            } else {
                this->coeffs[i].coeffs[j] = 0;
            }
        }
        ldaa_poly_ntt(this->coeffs[i].coeffs, n, q);
    }

}
