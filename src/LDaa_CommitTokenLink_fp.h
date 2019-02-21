#ifndef LDAA_COMMITTOKENLINK_FP_H
#define LDAA_COMMITTOKENLINK_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
    TPM2B_LDAA_BASENAME        bsn;
} LDAA_CommitTokenLink_In;

#define RC_LDAA_CommitTokenLink_key_handle	  (TPM_RC_P + TPM_RC_1)
#define RC_LDAA_CommitTokenLink_sid		      (TPM_RC_P + TPM_RC_2)
#define RC_LDAA_CommitTokenLink_bsn	          (TPM_RC_P + TPM_RC_3)

typedef struct {
    TPM2B_LDAA_NYM             nym;
    TPM2B_LDAA_PE              pe;
    TPM2B_LDAA_PBSN            pbsn;
} LDAA_CommitTokenLink_Out;

TPM_RC
TPM2_LDAA_CommitTokenLink(
         LDAA_CommitTokenLink_In      *in, // IN: input parameter list
		 LDAA_CommitTokenLink_Out     *out // OUT: output parameter list
		 );
#endif
