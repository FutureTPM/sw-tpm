#ifndef LDAA_JOIN_FP_H
#define LDAA_JOIN_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
    UINT8                      jsid;  // Unique submission Identifier
    TPM2B_NONCE                nonce;
    TPM2B_LDAA_BASENAME_ISSUER bsn_I; // Issuer basename
} LDAA_Join_In;

#define RC_LDAA_Join_key_handle		(TPM_RC_P + TPM_RC_1)
#define RC_LDAA_Join_sid		    (TPM_RC_P + TPM_RC_2)
#define RC_LDAA_Join_jsid		    (TPM_RC_P + TPM_RC_3)
#define RC_LDAA_Join_nonce		    (TPM_RC_P + TPM_RC_4)
#define RC_LDAA_Join_bsn_I		    (TPM_RC_P + TPM_RC_5)

typedef struct {
    TPM2B_LDAA_NYM          nym;
    TPM2B_LDAA_PUBLIC_KEY	public_key;
    // TODO: Add support for proof (pi)
} LDAA_Join_Out;

TPM_RC
TPM2_LDAA_Join(
         LDAA_Join_In      *in, // IN: input parameter list
		 LDAA_Join_Out     *out // OUT: output parameter list
		 );
#endif
