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

LIB_EXPORT TPM_RC
CryptLDaaJoin(
        // OUT: returned public Key
        TPM2B_LDAA_PUBLIC_KEY *public_key_serial,
        // OUT: return link token
        TPM2B_LDAA_NYM *nym_serial,
        // IN: public area to fetch the public key
        TPMT_PUBLIC    *publicArea,
        // IN: Issuer basename
        TPM2B_LDAA_BASENAME_ISSUER           *bsn_I,
        // IN: secret area to fetch the secret key
        TPMT_SENSITIVE *sensitive
        );

LIB_EXPORT TPM_RC
CryptLDaaClearProtocolState(void);

LIB_EXPORT TPM_RC
CryptLDaaCommit(void);

#endif
