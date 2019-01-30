#ifndef CRYPTLDAA_FP_H
#define CRYPTLDAA_FP_H

BOOL CryptLDaaInit(void);
BOOL CryptLDaaStartup(void);

LIB_EXPORT TPM_RC
CryptLDaaGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *ldaaKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		 );

#endif
