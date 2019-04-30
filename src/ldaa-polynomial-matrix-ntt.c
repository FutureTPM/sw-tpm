#include "ldaa-polynomial-matrix-ntt.h"
#include "ldaa-polynomial-matrix.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-params.h"

void ldaa_poly_matrix_ntt_commit1_product(ldaa_poly_matrix_ntt_commit1_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed)
{
    size_t i, j, k, l;
    UINT32 prod;
    TPM2B_SEED tpm2b_seed;
    ldaa_poly_t a;
    ldaa_poly_ntt_t a_ntt;
    DRBG_STATE rand;

    MemoryCopy(tpm2b_seed.b.buffer, &seed, sizeof(size_t));
    tpm2b_seed.b.size = sizeof(size_t);
    TPM2B_STRING(HOST_B_NTT_GENERATION, "Host B NTT Generation");
    DRBG_InstantiateSeeded(&rand, &tpm2b_seed.b,
            HOST_B_NTT_GENERATION, NULL, NULL);

    for (i = 0; i < LDAA_COMMIT1_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                ldaa_poly_sample_u(&a, &rand);
                for (l = 0; l < LDAA_N; l++) {
                    prod = ldaa_reduce((UINT64)a_ntt.coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] = this->coeffs[i * 1 + j].coeffs[l] + prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= LDAA_Q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= LDAA_Q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_commit2_product(ldaa_poly_matrix_ntt_commit2_prod_t *this,
		    ldaa_poly_matrix_ntt_R_t *b, size_t seed)
{
    size_t i, j, k, l;
    UINT32 prod;
    TPM2B_SEED tpm2b_seed;
    ldaa_poly_t a;
    ldaa_poly_ntt_t a_ntt;
    DRBG_STATE rand;

    MemoryCopy(tpm2b_seed.b.buffer, &seed, sizeof(size_t));
    tpm2b_seed.b.size = sizeof(size_t);
    TPM2B_STRING(HOST_B_NTT_GENERATION, "Host B NTT Generation");
    DRBG_InstantiateSeeded(&rand, &tpm2b_seed.b,
            HOST_B_NTT_GENERATION, NULL, NULL);

    for (i = 0; i < LDAA_COMMIT2_LENGTH; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < LDAA_K_COMM; k++) {
                ldaa_poly_sample_u(&a, &rand);
                for (l = 0; l < LDAA_N; l++) {
                    prod = ldaa_reduce((UINT64)a_ntt.coeffs[l] * b->coeffs[k * 1 + j].coeffs[l]);
                    this->coeffs[i * 1 + j].coeffs[l] = this->coeffs[i * 1 + j].coeffs[l] + prod;
                    if (this->coeffs[i * 1 + j].coeffs[l] >= LDAA_Q) {
                        this->coeffs[i * 1 + j].coeffs[l] -= LDAA_Q;
                    }
                }
            }
        }
    }
}

void ldaa_poly_matrix_ntt_R_commit_from_canonical(ldaa_poly_matrix_ntt_R_t *this,
			   ldaa_poly_matrix_R_commit_t *a)
{
    size_t i, j;
    for (i = 0; i < LDAA_K_COMM; i++) {
        for (j = 0; j < LDAA_N; j++) {
            if (j == 0) {
                this->coeffs[i].coeffs[j] = a->coeffs[i];
            } else {
                this->coeffs[i].coeffs[j] = 0;
            }
        }
        ldaa_poly_ntt(this->coeffs[i].coeffs);
    }

}
