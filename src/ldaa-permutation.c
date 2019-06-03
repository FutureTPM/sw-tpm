#include "ldaa-params.h"
#include "ldaa-permutation.h"
#include "ldaa-sample.h"
#include <math.h>
#include <stddef.h>

void ldaa_permutation_sample_u(ldaa_permutation_t *this,
        uint64_t log_w, uint64_t n)
{
    size_t i;
    size_t n_loop = (2*(1<<log_w)-1)*n;

    for (i = 0; i < n_loop; i++) {
        this->v[i] = i;
    }

    for (i = 0; i < n_loop-1; i++) {
        size_t j = floor(i + (n_loop - i) * ldaa_sample(NULL));
        UINT32 tmp = this->v[i];
        this->v[i] = this->v[j];
        this->v[j] = tmp;
    }
}

void ldaa_permutation_perm_sample_u(ldaa_permutation_perm_t *this,
        uint64_t log_w, uint64_t n)
{
    size_t i;
    size_t n_loop = (2*(1<<log_w)-2)*n;

    for (i = 0; i < n_loop; i++) {
        this->v[i] = i;
    }

    for (i = 0; i < n_loop-1; i++) {
        size_t j = floor(i + (n_loop - i) * ldaa_sample(NULL));
        UINT32 tmp = this->v[i];
        this->v[i] = this->v[j];
        this->v[j] = tmp;
    }
}

void ldaa_permutation_embed(ldaa_permutation_t *this, ldaa_poly_t *ps,
        uint64_t log_w, uint64_t n)
{
    const size_t m = (2*(1<<log_w)-1)*n;
    const size_t numpols = (m + ((n - (m % n)) % n)) / n;
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < n; j++) {
            if (i * n + j < m) {
                ps[i].coeffs[j] = this->v[i * n + j];
            }
        }
    }
}

void ldaa_permutation_copy(ldaa_permutation_t *this, ldaa_permutation_t *other,
        uint64_t log_w, uint64_t n)
{
    for (size_t i = 0; i < (2*(1<<log_w)-1)*n; i++) {
        other->v[i] = this->v[i];
    }
}
