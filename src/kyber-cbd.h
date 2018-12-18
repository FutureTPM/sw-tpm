#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "kyber-poly.h"

void kyber_cbd(kyber_poly *r, const unsigned char *buf, const uint64_t kyber_eta);

#endif
