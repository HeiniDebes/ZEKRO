#ifndef PROVER_H
#define PROVER_H

#include "tpm.h"

#include <string>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <fstream>
#include <random>
#include <sys/time.h>

struct mPCR {
    unsigned char    val[SHA256_DIGEST_SIZE];
    TPMI_RH_NV_INDEX idx;
    TPM2B_NAME       name;
    };

class Prover {
    public:
        Prover(TSS_CONTEXT* ctx, TPM2B_NAME orchestratorSigningKeyName, TPM2B_PUBLIC orchestratorSigningKeyPublic);
        ~Prover();
        CertifyCreation_Out createLak(const TPMA_OBJECT objectAttributes, const TPM2B_DIGEST* authPol);
        NV_Certify_Out createNvPcr(TPMI_RH_NV_INDEX idx, TPMA_NV objectAttributes, const TPM2B_DIGEST* authPol, const TPM2B_MAX_NV_BUFFER* iv);
        void update(const TPM2B_DIGEST* aPol, const TPMT_SIGNATURE* aHashSignature, const TPM2B_DIGEST* aHash);
        TPM2B_NONCE startSession();
        void lease(const TPMT_SIGNATURE* aHashSignature, INT32 exp, const TPM2B_DIGEST* cid);
        TPMT_SIGNATURE attest(TPM2B_DIGEST nonce);

        TPM2B_PUBLIC mIakPublic; // public part of prover's Initial Attestation Key
        TPM2B_PUBLIC mLakPublic; // public part of prover's Local Attestation Key
        TPM2B_PUBLIC mTeeSigningKeyPublic; // public part of the TEE's signing key
        TPM2B_DIGEST id;

    private:
        TSS_CONTEXT* mCtx;
        mPCR mpcr; // mock PCR of the TEE's NV PCR

        Create_Out iak;
        Create_Out lak;
        Create_Out teeSigningKey;

        TPM2B_NAME mOrchestratorSigningKeyName; // name of orchestrator's signing key
        TPM2B_PUBLIC mOrchestratorSigningKeyPublic; // public part of orchestrator's signing key
        StartAuthSession_Out leaseSession;
        TPM2B_DIGEST aPol;

        TPMT_TK_VERIFIED mTicket; // ticket for aPol's authenticity
        PolicySigned_Out mTicketLease; // expirable ticket from lease
        TPM2B_DIGEST cid;
};

#endif // PROVER_H
