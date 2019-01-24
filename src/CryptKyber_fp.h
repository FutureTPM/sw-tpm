#ifndef CRYPTKYBER_FP_H
#define CRYPTKYBER_FP_H

LIB_EXPORT BOOL CryptKyberInit(void);
LIB_EXPORT BOOL CryptKyberStartup(void);
LIB_EXPORT BOOL CryptKyberIsModeValid(
            // IN: the security mode
            TPM_KYBER_SECURITY  k
        );

LIB_EXPORT TPM_RC
CryptKyberGenerateKey(
            // IN/OUT: The object structure in which the key is created.
		    OBJECT              *dilithiumKey,
            // IN: if not NULL, the deterministic RNG state
		    RAND_STATE          *rand
		    );

LIB_EXPORT TPM_RC
CryptKyberEncapsulate(
            // IN: The object structure which contains the public key used in
            // the encapsulation.
		    TPMT_PUBLIC             *publicArea,
            // OUT: the shared key
            TPM2B_KYBER_SHARED_KEY  *ss,
            // OUT: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct
		 );

LIB_EXPORT TPM_RC
CryptKyberDecapsulate(
            // IN: The object structure which contains the secret key used in
            // the decapsulation.
		    TPMT_SENSITIVE          *sensitive,
            // IN: Kyber security mode
            TPM_KYBER_SECURITY      k,
            // IN: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct,
            // OUT: the shared key
            TPM2B_KYBER_SHARED_KEY  *ss
		 );

LIB_EXPORT TPM_RC
CryptKyberValidateCipherTextSize(
            // IN: the cipher text
            TPM2B_KYBER_CIPHER_TEXT *ct,
            // IN: the security mode being used to decapsulate the cipher text
            TPM_KYBER_SECURITY  k
		 );
#endif
