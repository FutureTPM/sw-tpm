#ifndef LDAA_SIGNPROCEED_FP_H
#define LDAA_SIGNPROCEED_FP_H

typedef struct {
    TPMI_DH_OBJECT             key_handle;
    UINT8                      sid;   // Session ID
} LDAA_SignProceed_In;

#define RC_LDAA_SignProceed_key_handle	(TPM_RC_P + TPM_RC_1)
#define RC_LDAA_SignProceed_sid		    (TPM_RC_P + TPM_RC_2)

TPM_RC
TPM2_LDAA_SignProceed(
         LDAA_SignProceed_In      *in // IN: input parameter list
		 );
#endif
