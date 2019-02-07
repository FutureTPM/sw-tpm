#ifndef LDAA_SIGNCOMMIT_FP_H
#define LDAA_SIGNCOMMIT_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
    UINT8                      ssid;
    TPM2B_LDAA_BASENAME        bsn;
    TPM2B_LDAA_ISSUER_ATNTT    issuer_at_ntt;
    TPM2B_LDAA_ISSUER_BNTT     issuer_bntt;
    TPM2B_LDAA_ISSUER_BNTT2    issuer_bntt2;
    TPM2B_LDAA_ISSUER_BNTT3    issuer_bntt3;
} LDAA_SignCommit_In;

#define RC_LDAA_SignCommit_key_handle	 (TPM_RC_P + TPM_RC_1)
#define RC_LDAA_SignCommit_sid		     (TPM_RC_P + TPM_RC_2)
#define RC_LDAA_SignCommit_ssid		     (TPM_RC_P + TPM_RC_3)
#define RC_LDAA_SignCommit_bsn	         (TPM_RC_P + TPM_RC_4)
#define RC_LDAA_SignCommit_issuer_at_ntt (TPM_RC_P + TPM_RC_5)
#define RC_LDAA_SignCommit_issuer_bntt	 (TPM_RC_P + TPM_RC_6)
#define RC_LDAA_SignCommit_issuer_bntt2	 (TPM_RC_P + TPM_RC_7)
#define RC_LDAA_SignCommit_issuer_bntt3	 (TPM_RC_P + TPM_RC_8)

typedef struct {
    UINT8                   sid;   // Session ID
    UINT8                   ssid;
    TPM2B_LDAA_C1           c1;
    TPM2B_LDAA_C2           c2;
    TPM2B_LDAA_C3           c3;
} LDAA_SignCommit_Out;

TPM_RC
TPM2_LDAA_SignCommit(
         LDAA_SignCommit_In      *in, // IN: input parameter list
		 LDAA_SignCommit_Out     *out // OUT: output parameter list
		 );
#endif
