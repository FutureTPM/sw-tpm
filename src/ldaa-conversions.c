#include "ldaa-conversions.h"
#include "ldaa-params.h"
#include <stddef.h>

static void decompose_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp)
{
    size_t i, j;
    UINT32 mask = (1<<LDAA_LOG_W)-1;
    size_t shift_amount = 0;

    for (i = 0; i < LDAA_LOG_BETA; i++) {
        for (j = 0; j < LDAA_N; j++) {
            UINT32 pj = p->coeffs[j];
            BOOL neg = pj > LDAA_Q/2;
            if (!neg) {
                pdecomp[i].coeffs[j] = (pj >> shift_amount) & mask;
            } else {
                pj = LDAA_Q - pj;
                UINT32 word = (pj >> shift_amount) & mask;
                pdecomp[i].coeffs[j] = (word == 0 ? 0 : LDAA_Q - word);
            }
        }

        shift_amount += LDAA_LOG_W;
    }
}

void
decompose_extend_w(ldaa_poly_t *p, ldaa_integer_matrix_t *pdecomp)
{
    decompose_w(p, pdecomp);
    size_t i, j, jj;
    UINT32 w = (1<<LDAA_LOG_W);
    size_t count[2*w - 1];

    for (i = 0; i < LDAA_LOG_BETA; i++) {
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
        for (j = 0; j < LDAA_N; j++) {
            UINT32 pij = pdecomp[i].coeffs[j];
            if (pij < LDAA_Q/2) {
                count[pij]++;
            } else {
                count[2*w-1-(LDAA_Q-pij)]++;
            }
        }
        /* count[0] + ... + count[2*w - 2] = n */
        /* (n-count[0]) + ... + (n-count[2*w - 2]) = (2*w-2)*n */

        ldaa_integer_matrix_pext_t pext;

        size_t block_init = 0;
        for (j = 0; j < 2*w - 1; j++) {
            size_t next_block = block_init + (LDAA_N - count[j]);
            UINT32 word = j;

            if (word >= w) {
                word = LDAA_Q - (2*w-1 - word);
            }

            for (jj = block_init; jj < next_block; jj++) {
                pext.coeffs[jj] = word;
            }

            block_init = next_block;
        }

        ldaa_permutation_perm_t perm;
        ldaa_permutation_perm_sample_u(&perm);

        ldaa_integer_matrix_pext_permute(&pext, &perm);

        ldaa_integer_matrix_append_rows_pext(&pdecomp[i], &pext);
    }
}

void fold_embed(ldaa_integer_matrix_t *vs, ldaa_poly_t *res) {
    UINT64 xs[LDAA_N];
    size_t i, j;
    const UINT8 shift_amount[LDAA_LOG_BETA] = {0, 1, 2, 3, 4, 5, 6, 7};

    for (i = 0; i < LDAA_N; i++) {
        xs[i] = 0;
    }

    for (i = 0; i < LDAA_LOG_BETA; i++) {
        ldaa_integer_matrix_t *vi = &vs[i];

        for (j = 0; j < LDAA_N; j++) {
            xs[j] += (vi->coeffs[j] << (shift_amount[i] & 0x1f));
        }
    }

    for (j = 0; j < LDAA_N; j++) {
        res->coeffs[j] = ldaa_reduce(xs[j]);
    }
}

void embed_1(ldaa_integer_matrix_t *v, ldaa_poly_t *ps)
{
    const size_t m = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;
    const size_t numpols = (m + ((LDAA_N - (m % LDAA_N)) % LDAA_N)) / LDAA_N;
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < LDAA_N; j++) {
            UINT32 pi;
            if (i * LDAA_N + j < m) {
                pi = v->coeffs[i * LDAA_N + j];
            } else {
                pi = 0;
            }
            ps[i].coeffs[j] = pi;
        }
    }
}
