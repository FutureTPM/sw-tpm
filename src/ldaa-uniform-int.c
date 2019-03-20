#include "ldaa-uniform-int.h"
#include "ldaa-sample.h"
#include <math.h>

INT32 ldaa_uniform_int_sample(INT32 a, INT32 b, DRBG_STATE *state)
{
  double myRand = 1.0;

  myRand = ldaa_sample(state);

  myRand = a + (b-a) * myRand;

  return floor(myRand);
}
