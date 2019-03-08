#include "Tpm.h"
#include "ldaa-params.h"
#include "ldaa-permutation.h"
#include "ldaa-sample.h"
#include <math.h>

void ldaa_permutation_sample_u(ldaa_permutation_t *this)
{
  size_t i;
  size_t n = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;

  for (i = 0; i < n; i++) {
    this->v[i] = i;
  }

  for (i = 0; i < n-1; i++) {
    size_t j = floor(i + (n - i) * ldaa_sample());
    UINT32 tmp = this->v[i];
    this->v[i] = this->v[j];
    this->v[j] = tmp;
  }
}

void ldaa_permutation_perm_sample_u(ldaa_permutation_perm_t *this)
{
  size_t i;
  size_t n = (2*(1<<LDAA_LOG_W)-2)*LDAA_N;

  for (i = 0; i < n; i++) {
    this->v[i] = i;
  }

  for (i = 0; i < n-1; i++) {
    size_t j = floor(i + (n - i) * ldaa_sample());
    UINT32 tmp = this->v[i];
    this->v[i] = this->v[j];
    this->v[j] = tmp;
  }
}

void ldaa_permutation_embed(ldaa_permutation_t *this, ldaa_poly_t *ps)
{
    const size_t m = (2*(1<<LDAA_LOG_W)-1)*LDAA_N;
    const size_t numpols = (m + ((LDAA_N - (m % LDAA_N)) % LDAA_N)) / LDAA_N;
    size_t i, j;

    for (i = 0; i < numpols; i++) {
        for (j = 0; j < LDAA_N; j++) {
            if (i * LDAA_N + j < m) {
                ps[i].coeffs[j] = this->v[i * LDAA_N + j];
            }
        }
    }
}

void ldaa_permutation_copy(ldaa_permutation_t *this, ldaa_permutation_t *other)
{
    for (size_t i = 0; i < (2*(1<<LDAA_LOG_W)-1)*LDAA_N; i++) {
        other->v[i] = this->v[i];
    }
}
