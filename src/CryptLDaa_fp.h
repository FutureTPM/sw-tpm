/*
 * MIT License
 *
 * Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef CRYPTLDAA_FP_H
#define CRYPTLDAA_FP_H

BOOL CryptLDaaInit(void);
BOOL CryptLDaaStartup(void);

LIB_EXPORT BOOL CryptLDaaIsModeValid(
            // IN: the security mode
            TPM_LDAA_SECURITY_MODE  security
        );

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

LIB_EXPORT TPM_RC
CryptLDaaSignCommit(
        // OUT: Result of commit
        TPM2B_LDAA_COMMIT *c_out,
        // IN: Serialized private key
        TPMT_SENSITIVE    *sensitive,
        // IN: commit selection
        BYTE              *commit_sel,
        // IN: sign state selection
        BYTE              *sign_state_sel,
        // IN: Serialized polynomial of the hash of the basename
        TPM2B_LDAA_PBSN   *pbsn_serial,
        // IN: Serialized error polynomial
        TPM2B_LDAA_PE     *pe_serial,
        // IN: Serialized key
        TPM2B_LDAA_ISSUER_ATNTT *issuer_atntt_serial,
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn,
        // IN: Offset to process the Commit 2 and 3
        UINT32              *seed,
        // IN: Security Mode used in the LDAA key
        BYTE security
        );

LIB_EXPORT TPM_RC
CryptLDaaCommitTokenLink(
        // OUT: Serialized token link
        TPM2B_LDAA_NYM *nym_serial,
        // OUT: Serialized polynomial of the hash of the basename
        TPM2B_LDAA_PBSN *pbsn_serial,
        // OUT: Serialized error polynomial
        TPM2B_LDAA_PE   *pe_serial,
        // IN: Serialized private key
        TPMT_SENSITIVE *sensitive,
        // IN: Basename to be used in the commit
        TPM2B_LDAA_BASENAME *bsn,
        // IN: Security Mode used in the LDAA key
        BYTE security
        );

LIB_EXPORT TPM_RC
CryptLDaaSignProof(
        // OUT: sign state R1
        TPM2B_LDAA_SIGN_STATE   *R1_out_serial,
        // OUT: sign state R2
        TPM2B_LDAA_SIGN_STATE   *R2_out_serial,
        // OUT: Sign Group
        TPM2B_LDAA_SIGN_GROUP   *sign_group_serial,
        // IN:  sign state R1
        TPM2B_LDAA_SIGN_STATE   *R1_in_serial,
        // IN:  sign state R2
        TPM2B_LDAA_SIGN_STATE   *R2_in_serial,
        // IN: sign state selection
        BYTE                    *sign_state_sel,
        // IN: Sign State type
        BYTE                    *sign_state_type,
        // IN: Security Mode used in the LDAA key
        BYTE security
        );
#endif
