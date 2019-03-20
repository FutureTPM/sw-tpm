#include "ldaa-params.h"
#include "ldaa-sample.h"


double ldaa_sample(DRBG_STATE *state)
{
    double myRand = 1.0;
    UINT64 significand;
    BYTE buffer[sizeof(UINT64)];

    // Generate random value in [1.0, 2.0[ because they share the same exponent
    // 0x3ff
    while (myRand < 0.0 || myRand >= 1.0) {
        // Randomly generate 64 bits
        // Check reseed counter before generating random bytes
        if (state != NULL && state->reseedCounter == CTR_DRBG_MAX_REQUESTS_PER_RESEED) {
            DRBG_Reseed(state, NULL, NULL);
        }
        UINT16 res = DRBG_Generate((RAND_STATE *)state, buffer, sizeof(UINT64));
        if (res == 0) {
            FAIL(FATAL_ERROR_INTERNAL);
        }
        MemoryCopy(&significand, buffer, sizeof(UINT64));

        // Build double
        UINT64 tmp = (0x3ffUL << 52) // sign and exponent
            |    (significand & 0xfffffffffffffUL);
        MemoryCopy(&myRand, &tmp, sizeof(double));

        // Then make sure result is between [0.0, 1.0[
        myRand -= 1.0;
    }

    return myRand;
}
