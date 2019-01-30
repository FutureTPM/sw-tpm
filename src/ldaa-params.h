#ifndef LDAA_PARAMS_H
#define LDAA_PARAMS_H

#define LDAA_M 24
#define LDAA_Q 8380417
#define LDAA_N 256
#define LDAA_S 6

#define LDAA_SECRET_KEY_LENGTH (LDAA_M*LDAA_N) // Column of DAA_N polynomials
#define LDAA_PUBLIC_KEY_LENGTH LDAA_N // polynomial

#endif
