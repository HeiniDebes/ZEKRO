#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tsstransmit.h>

#include <cryptoutils.h>
#include <openssl/rand.h>

void boot(TSS_CONTEXT* ctx);
TPM_RC prettyRC(const TPM_RC rc, const char* callerFunc);
void   prettyRC(const TPM_RC rc, const char* callerFunc, TSS_CONTEXT* ctx);
TPM_RC createPrimaryKey(TSS_CONTEXT* ctx, 
                const TPMI_RH_HIERARCHY hierarchy,
                const char*             parentPassword,
                const char*             keyPass,
                const TPM2B_DIGEST*     policyDigest,
				CreatePrimary_Out*      out);
Create_Out create(TSS_CONTEXT* ctx, 
				const TPM_HANDLE    parentHandle,
				const char*         parentPassword,
				const TPMA_OBJECT   objectAttributes,
				unsigned char*      keyPassword,
				const TPM2B_DIGEST* authPolicy);
TPM_RC evictControl(TSS_CONTEXT* ctx, 
				const TPMI_RH_PROVISION  auth,
				const TPMI_DH_OBJECT     objectHandle,
				const TPMI_DH_PERSISTENT persistentHandle);
Load_Out load(TSS_CONTEXT* ctx,
                const TPMI_DH_OBJECT parentHandle,
                const char*          parentPassword,
                const Create_Out&    sealedKey);
LoadExternal_Out loadExternal(TSS_CONTEXT* ctx,
				const TPMI_RH_HIERARCHY hierarchy,
				const TPM2B_SENSITIVE*  inPrivate,
				const TPM2B_PUBLIC*     inPublic);
CertifyCreation_Out certifyCreation(TSS_CONTEXT* ctx, 
                const TPMI_DH_OBJECT       objectHandle,
                const TPMI_DH_OBJECT       signHandle, 
                const TPM2B_DIGEST*        creationHash, 
                const TPMT_TK_CREATION*    creationTicket,
                const char*                keyPassword,
                const TPMI_SH_AUTH_SESSION sessionHandle0,
                const unsigned int         sessionAttributes0,
                const TPMI_SH_AUTH_SESSION sessionHandle1,
                const unsigned int         sessionAttributes1,
                const TPMI_SH_AUTH_SESSION sessionHandle2,
                const unsigned int         sessionAttributes2);
TPMT_SIGNATURE sign(TSS_CONTEXT* ctx,
                const TPM2B_DIGEST*        digest, 
                const TPMI_DH_OBJECT       keyHandle,
                const TPMT_TK_HASHCHECK*   validation,
				const TPMI_SH_AUTH_SESSION sessionHandle0, 
				const unsigned int         sessionAttributes0);
TPMT_TK_VERIFIED verifySignature(TSS_CONTEXT* ctx,
				const TPM2B_DIGEST*   digest,
				const TPMI_DH_OBJECT  keyHandle,
				const TPMT_SIGNATURE* signature);
TPM_RC policyTicket(TSS_CONTEXT* ctx,
				const TPM2B_NONCE*   policyRef,
				const TPMI_SH_POLICY policySession,
				const TPM2B_NAME     authName,
				const TPMT_TK_AUTH   ticket,
				const TPM2B_TIMEOUT  timeout);
TPM_RC policyAuthorize(TSS_CONTEXT* ctx,
				const TPMI_SH_POLICY    policySession,
				const TPM2B_DIGEST*     approvedPolicy,
				const TPM2B_NONCE*      policyRef,
				const TPM2B_NAME        keySign,
				const TPMT_TK_VERIFIED* checkTicket);
PolicySigned_Out policySigned(TSS_CONTEXT* ctx,
				const TPMT_SIGNATURE*      auth,
				const TPMI_DH_OBJECT       authObject,
				const TPM2B_DIGEST*        cpHashA,
				const INT32                expiration,
				const TPM2B_NONCE*         nonceTPM,
				const TPM2B_NONCE*         policyRef,
				const TPMI_SH_POLICY       policySession);
void policyNv(TSS_CONTEXT* ctx,
				const TPMI_RH_NV_AUTH      authHandle,
				const TPMI_RH_NV_INDEX     nvIndex,
				const UINT16               offset,
				const TPM2B_OPERAND        operandB,
				const TPM_EO               operation,
				const TPMI_SH_POLICY       policySession,
				const TPMI_SH_AUTH_SESSION sessionHandle0,
				const unsigned int         sessionAttributes0);
TPM_RC startAuthSession(TSS_CONTEXT* ctx, const TPM_SE sessionType, StartAuthSession_Out* out);
void flushContext(TSS_CONTEXT* ctx, const TPMI_DH_CONTEXT flushHandle);
void nvDefineSpace(TSS_CONTEXT* ctx,
				const TPMI_RH_PROVISION authHandle,
				const TPMI_RH_NV_INDEX  nvIndex,
				const TPMI_ALG_HASH     nameAlg,
				const TPMA_NV           attributes,
				const UINT16            dataSize,
				const TPM2B_AUTH*       auth,
				const TPM2B_DIGEST*     authPolicy);
void nvUndefineSpace(TSS_CONTEXT* ctx, 
				const TPMI_RH_PROVISION authHandle,
				const TPMI_RH_NV_INDEX  nvIndex);
void nvExtend(TSS_CONTEXT* ctx,
				const TPMI_RH_PROVISION    authHandle,
				const TPM2B_MAX_NV_BUFFER* data,
				const TPMI_RH_NV_INDEX     nvIndex,
				const TPMI_SH_AUTH_SESSION sessionHandle0,
				const unsigned int         sessionAttributes0,
				const TPMI_SH_AUTH_SESSION sessionHandle1,
				const unsigned int         sessionAttributes1);
NV_Certify_Out nvCertify(TSS_CONTEXT* ctx,
				const TPMI_RH_NV_AUTH  authHandle,
				const TPMI_RH_NV_INDEX nvIndex,
				const UINT16           offset,
				const TPMI_DH_OBJECT   signHandle,
				const UINT16           size);
void clear(TSS_CONTEXT* ctx,
				const TPMI_RH_CLEAR authHandle,
				const char*         authPassword);
TPM2B_NAME getNameFromPublic(const TPMT_PUBLIC* pubKey, const TPMS_NV_PUBLIC* pubNv);
Hash_Out hash(TSS_CONTEXT* ctx,
				const TPM2B_MAX_BUFFER  data,
				const TPMI_ALG_HASH     hashAlg,
				const TPMI_RH_HIERARCHY hierarchy);
