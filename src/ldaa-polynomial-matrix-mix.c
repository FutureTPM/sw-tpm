#include "ldaa-polynomial-matrix-mix.h"
#include "BaseTypes.h"
#include "Memory_fp.h"

void ldaa_poly_matrix_commit1_prod_from_ntt(ldaa_poly_matrix_commit1_t *this,
	 ldaa_poly_matrix_ntt_commit1_prod_t *a,
     uint64_t commit1_len, uint64_t n, uint64_t q)
{
    size_t i, k;

    for (i = 0; i < commit1_len; i++) {
        for (k = 0; k < n; k++) {
            this->coeffs[i].coeffs[k] = a->coeffs[i].coeffs[k];
        }
        ldaa_poly_invntt(this->coeffs[i].coeffs, n, q);
    }
}

void ldaa_poly_matrix_commit1_product_ntt_1(ldaa_poly_matrix_commit1_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed,
              uint64_t commit1_len, uint64_t n, uint64_t q, uint64_t k_comm)
{
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba, n, k_comm, q);
    static ldaa_poly_matrix_ntt_commit1_prod_t prod;
    // Zero prod
    MemorySet(prod.coeffs, 0, commit1_len * n * sizeof(UINT32));
    ldaa_poly_matrix_ntt_commit1_product(&prod, &b, seed, commit1_len,
            n, k_comm, q);

    ldaa_poly_matrix_commit1_prod_from_ntt(this, &prod, commit1_len, n, q);
}

void ldaa_poly_matrix_commit2_prod_from_ntt(ldaa_poly_matrix_commit2_t *this,
	 ldaa_poly_matrix_ntt_commit2_prod_t *a, uint64_t commit2_len,
     uint64_t n, uint64_t q)
{
    size_t i, k;

    for (i = 0; i < commit2_len; i++) {
        for (k = 0; k < n; k++) {
            this->coeffs[i].coeffs[k] = a->coeffs[i].coeffs[k];
        }
        ldaa_poly_invntt(this->coeffs[i].coeffs, n, q);
    }
}

void ldaa_poly_matrix_commit2_product_ntt_1(ldaa_poly_matrix_commit2_t *this,
			  ldaa_poly_matrix_R_commit_t *ba, size_t seed,
              uint64_t commit2_len, uint64_t n, uint64_t q, uint64_t k_comm)
{
    // ldaa_poly_matrix_ntt_B2_t *a,
    ldaa_poly_matrix_ntt_R_t b;
    ldaa_poly_matrix_ntt_R_commit_from_canonical(&b, ba, n, k_comm, q);
    static ldaa_poly_matrix_ntt_commit2_prod_t prod;
    // Zero prod
    MemorySet(prod.coeffs, 0, commit2_len * n * sizeof(UINT32));
    ldaa_poly_matrix_ntt_commit2_product(&prod, &b, seed, commit2_len,
            n, k_comm, q);

    ldaa_poly_matrix_commit2_prod_from_ntt(this, &prod, commit2_len, n, q);
}
