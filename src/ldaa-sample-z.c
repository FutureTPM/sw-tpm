#include "ldaa-params.h"
#include "ldaa-sample-z.h"
#include "ldaa-sample.h"
#include "BaseTypes.h"
#include "Implementation.h"
#include <math.h>

static double ldaa_rho(double x, double c, double s)
{
  const double pi = 3.14159265358979323846;
  double sqdist = (x-c) * (x-c);
  return exp(-pi * sqdist / (s*s));
}

INT32 ldaa_sample_z(double c, double s, DRBG_STATE *state)
{
  double a = ceil(c - s * 8);
  double b = floor(c + s * 8);
  BOOL end = FALSE;
  int32_t x;

  do {
    double myRand = ldaa_sample(state);
    x = floor(a + (b-a) * myRand);
    double exitRand = ldaa_sample(state);
    if (exitRand < ldaa_rho(x, c, s))
      end = TRUE;
  } while(!end);

  return x;
}
