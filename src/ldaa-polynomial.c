#include "ldaa-params.h"
#include "ldaa-polynomial.h"
#include "ldaa-polynomial-consts.h"
#include "ldaa-polynomial-ntt.h"
#include "ldaa-sample-z.h"
#include "ldaa-uniform-int.h"
#include <stddef.h>
#include "Memory_fp.h"

UINT32 ldaa_reduce_8380417(UINT64 x)
{
    /* Input x is 0 <= x < 2^46 */
    /* 2^23 = 2^13 - 1 mod 8380417 */
    UINT32 x0 = x & ((1ULL<<23)-1);
    UINT32 x1 = (x >> 23) & ((1ULL<<10)-1);
    UINT32 x2 = (x >> 33) & ((1ULL<<10)-1);
    UINT32 x3 = (x >> 43);

    UINT32 z0 = x0;
    UINT32 z1 = x1 | (x2<<10) | (x3<<20);
    UINT32 z2 = x2 | (x3<<10);
    UINT32 z3 = x2<<13;
    UINT32 z4 = (x3<<13)-x3;
    UINT32 z5 = (x1<<13);

    UINT32 z = z0 - z1 - z2 + z3 + z4 + z5;

    while (z > (LDAA_HIGH_Q<<2)) z += LDAA_HIGH_Q; /* overflow due to subs */
    while (z >= LDAA_HIGH_Q) z -= LDAA_HIGH_Q;

    return z;
}

UINT32 ldaa_reduce_3329(UINT64 x)
{
    return x % 3329;
}

static UINT32 ceillog2(UINT32 q);
static void bit_swap(UINT32 *xs, uint64_t n)
{
    const UINT64 logn = ceillog2(n);
    UINT8 j;
    UINT16 i;

    for (i = 0; i < n; i++) {
        UINT8 itarget = 0;
        for (j = 0; j < logn; j++) {
            UINT64 bit = (i >> j) & 1;
            itarget |= bit << (logn - 1 - j);
        }

        if (itarget > i) {
            UINT32 tmp = xs[i];
            xs[i] = xs[itarget];
            xs[itarget] = tmp;
        }
    }
}

static void ntt_plain(UINT32 *xs, const UINT32 *ws, uint64_t n, uint64_t q)
{
    UINT8 N, i, j;
    UINT16 h = 0;
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

    bit_swap(xs, n);

    for (N = n/2; N > 0; N /= 2) {
        UINT16 k = n / N;
        /* UINT32 wN = powm(w, N, LDAA_Q); */

        for (i = 0; i < N; i++) {
            /* UINT32 wi = 1; */
            for (j = 0; j < k/2; j++) {
                UINT32 wi = ws[h++];
                UINT32 yek = xs[(UINT8)(i * k + j)];
                UINT32 yok = xs[(UINT8)(i * k + k/2 + j)];
                yok = reduce((UINT64)yok * wi);

                xs[(UINT8)(i * k + j)] = yek + yok;
                if (xs[(UINT8)(i * k + j)] >= q)
                    xs[(UINT8)(i * k + j)] -= q;

                xs[(UINT8)(i * k + k/2 + j)] = (yek < yok ? q : 0) + yek - yok;

                /* wi = reduce((UINT64)wi * wN); */
            }
        }
    }
}

void ldaa_poly_sample_z(ldaa_poly_t *this, uint64_t n, uint64_t s, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        INT32 x = ldaa_sample_z(0, s, NULL);
        this->coeffs[i] = (x < 0 ? q : 0) + x;
    }
}

void ldaa_poly_add(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b,
        uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out->coeffs[i] = a->coeffs[i] + b->coeffs[i];
        if (out->coeffs[i] >= q) {
            out->coeffs[i] -= q;
        }
    }
}

void ldaa_poly_sample_u(ldaa_poly_t *out, DRBG_STATE *state, uint64_t n, uint64_t q)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out->coeffs[i] = ldaa_uniform_int_sample(0, q, state);
    }
}

void ldaa_poly_mul(ldaa_poly_t *out, ldaa_poly_t *a, ldaa_poly_t *b,
        uint64_t n, uint64_t q)
{
    size_t i;
    // This is unsafe
    UINT32 b1[n];
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

    MemoryCopy(b1, b->coeffs, n * sizeof(UINT32));
    MemoryCopy(out->coeffs, a->coeffs, n * sizeof(UINT32));

    ldaa_poly_ntt(out->coeffs, n, q);
    ldaa_poly_ntt(b1, n, q);

    for (i = 0; i < n; i++) {
        out->coeffs[i] = reduce((UINT64)out->coeffs[i] * b1[i]);
    }

    ldaa_poly_invntt(out->coeffs, n, q);
}

void ldaa_poly_ntt(UINT32 *xs, uint64_t n, uint64_t q)
{
    size_t i;
    const UINT32* ldaa_psis = NULL;
    const UINT32* ldaa_ws = NULL;
    UINT32 (*reduce)(UINT64 x);

    switch (n) {
        case LDAA_WEAK_N:
            ldaa_psis = LDAA_WEAK_PSIS;
            ldaa_ws = LDAA_WEAK_WS;
            reduce = ldaa_reduce_3329;
            break;
        case LDAA_MEDIUM_N:
            ldaa_psis = LDAA_MEDIUM_PSIS;
            ldaa_ws = LDAA_MEDIUM_WS;
            reduce = ldaa_reduce_8380417;
            break;
        case LDAA_HIGH_N:
            ldaa_psis = LDAA_HIGH_PSIS;
            ldaa_ws = LDAA_HIGH_WS;
            reduce = ldaa_reduce_8380417;
            break;
        default:
            break;
    }

    for (i = 0; i < n; i++) {
        xs[i] = reduce((UINT64)xs[i] * ldaa_psis[i]);
    }

    ntt_plain(xs, ldaa_ws, n, q);
}

void ldaa_poly_invntt(UINT32 *xs, uint64_t n, uint64_t q)
{
    size_t i;
    const UINT32* ldaa_psisinv = NULL;
    const UINT32* ldaa_wsinv = NULL;
    UINT32 (*reduce)(UINT64 x);

    switch (n) {
        case LDAA_WEAK_N:
            ldaa_psisinv = LDAA_WEAK_PSISINV;
            ldaa_wsinv = LDAA_WEAK_WSINV;
            reduce = ldaa_reduce_3329;
            break;
        case LDAA_MEDIUM_N:
            ldaa_psisinv = LDAA_MEDIUM_PSISINV;
            ldaa_wsinv = LDAA_MEDIUM_WSINV;
            reduce = ldaa_reduce_8380417;
            break;
        case LDAA_HIGH_N:
            ldaa_psisinv = LDAA_HIGH_PSISINV;
            ldaa_wsinv = LDAA_HIGH_WSINV;
            reduce = ldaa_reduce_8380417;
            break;
        default:
            break;
    }

    ntt_plain(xs, ldaa_wsinv, n, q);

    for (i = 0; i < n; i++) {
        xs[i] = reduce((UINT64)xs[i] * ldaa_psisinv[i]);
    }
}

static UINT32 ceillog2(UINT32 q)
{
    size_t i = 0;

    while ((1ULL << i) < q) i++;

    return i;
}

void ldaa_poly_from_hash(
        // OUT: Resulting polynomial from the Hash
        ldaa_poly_t *out,
        // IN: Hash digest to convert
        BYTE *digest,
        uint64_t n,
        uint64_t q
        ) {
    size_t bits_consumed = 0;
    size_t j, k;
    UINT32 pi;
    UINT32 logq = ceillog2(q);
    UINT32 mask = (1ULL << logq)-1;

    for (size_t i = 0; i < n; i++) {
        do {
            if (bits_consumed + logq >= (SHA256_DIGEST_SIZE * 8)) return;

            pi = digest[bits_consumed / 8] >> (bits_consumed % 8);
            k = 8 - (bits_consumed % 8);
            j = 1;
            while (k < logq) {
                pi += digest[bits_consumed / 8 + j] << k;
                k += 8;
                j++;
            }

            if (k > logq) pi &= mask;

            bits_consumed += logq;
        } while (pi >= q);

        out->coeffs[i] = pi;
    }
}

