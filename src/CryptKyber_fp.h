#ifndef CRYPTKYBER_FP_H
#define CRYPTKYBER_FP_H

LIB_EXPORT BOOL CryptKyberInit(void);
LIB_EXPORT BOOL CryptKyberStartup(void);

LIB_EXPORT TPM_RC
CryptKyberGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *dilithiumKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    );
#endif
