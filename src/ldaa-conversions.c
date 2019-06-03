#include "ldaa-conversions.h"
#include "ldaa-params.h"
#include <stddef.h>

static void decompose_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp,
        uint64_t log_w, uint64_t log_beta, uint64_t n, uint64_t q)
{
    size_t i, j;
    UINT32 mask = (1<<log_w)-1;
    size_t shift_amount = 0;

    for (i = 0; i < log_beta; i++) {
        for (j = 0; j < n; j++) {
            UINT32 pj = p->coeffs[j];
            BOOL neg = pj > q/2;
            if (!neg) {
                pdecomp[i].coeffs[j] = (pj >> shift_amount) & mask;
            } else {
                pj = q - pj;
                UINT32 word = (pj >> shift_amount) & mask;
                pdecomp[i].coeffs[j] = (word == 0 ? 0 : q - word);
            }
        }

        shift_amount += log_w;
    }
}

void
decompose_extend_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp,
        uint64_t log_w, uint64_t log_beta, uint64_t n, uint64_t q)
{
    decompose_w(p, pdecomp, log_w, log_beta, n, q);
    size_t i, j, jj;
    UINT32 w = (1<<log_w);
    size_t count[2*w - 1];

    for (i = 0; i < log_beta; i++) {
        for (j = 0; j < 2*w-1; j++) {
            count[j] = 0;
        }

        /* count[0] .. amount of 0s in pdecomp[i]
        count[1] .. amount of 1s in pdecomp[i]
        ...
        count[w-1] .. amount of (w-1)s in pdecomp[i]
        count[w] .. amount of (-w+1)s in pdecomp[i]
        ...
        count[2*w-2] .. amount of (-1)s in pdecomp[i]
        */
        for (j = 0; j < n; j++) {
            UINT32 pij = pdecomp[i].coeffs[j];
            if (pij < q/2) {
                count[pij]++;
            } else {
                count[2*w-1-(q-pij)]++;
            }
        }
        /* count[0] + ... + count[2*w - 2] = n */
        /* (n-count[0]) + ... + (n-count[2*w - 2]) = (2*w-2)*n */

        ldaa_integer_matrix_pext_t pext;

        size_t block_init = 0;
        for (j = 0; j < 2*w - 1; j++) {
            size_t next_block = block_init + (n - count[j]);
            UINT32 word = j;

            if (word >= w) {
                word = q - (2*w-1 - word);
            }

            for (jj = block_init; jj < next_block; jj++) {
                pext.coeffs[jj] = word;
            }

            block_init = next_block;
        }

        ldaa_permutation_perm_t perm;
        ldaa_permutation_perm_sample_u(&perm, log_w, n);

        ldaa_integer_matrix_pext_permute(&pext, &perm, log_w, n);

        ldaa_integer_matrix_append_rows_pext(&pdecomp[i], &pext, log_w, n);
    }
}

void fold_embed(ldaa_integer_matrix_t *vs, ldaa_poly_t *res,
        uint64_t log_beta, uint64_t log_w, uint64_t n) {
    // This is unsafe
    UINT64 xs[n];
    size_t i, j;
    size_t shift_amount = 0;
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
        xs[i] = 0;
    }

    for (i = 0; i < log_beta; i++) {
        ldaa_integer_matrix_t *vi = &vs[i];

        for (j = 0; j < n; j++) {
            xs[j] += (vi->coeffs[j] << shift_amount);
        }

        shift_amount += log_w;
    }

    for (j = 0; j < n; j++) {
        res->coeffs[j] = reduce(xs[j]);
    }
}

void embed_1(ldaa_integer_matrix_t *v, ldaa_poly_t *ps,
        uint64_t log_w, uint64_t n)
{
    const size_t m = (2*(1<<log_w)-1)*n;
    const size_t numpols = (m + ((n - (m % n)) % n)) / n;
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < n; j++) {
            UINT32 pi;
            if (i * n + j < m) {
                pi = v->coeffs[i * n + j];
            } else {
                pi = 0;
            }
            ps[i].coeffs[j] = pi;
        }
    }
}
