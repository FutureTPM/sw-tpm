#include "ldaa-params.h"
#include "ldaa-sample.h"
#include <stdlib.h>

// TODO: Run srand? Maybe?
double ldaa_sample(void)
{
  double myRand = 1.0;

  while (myRand == 1.0)
    myRand = drand48();

  return myRand;
}
