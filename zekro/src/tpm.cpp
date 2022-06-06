#include "tpm.h"
#include "timing.h"

void boot(TSS_CONTEXT* ctx) {
#ifndef HWTPM
	TSS_CONTEXT* tmpCtx = nullptr;
	prettyRC(TSS_Create(&tmpCtx), __func__, ctx);
	prettyRC(TSS_TransmitPlatform(tmpCtx, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform"), __func__, ctx);
	prettyRC(TSS_TransmitPlatform(tmpCtx, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform"), __func__, ctx);
	prettyRC(TSS_TransmitPlatform(tmpCtx, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform"), __func__, ctx);
	TSS_Delete(tmpCtx);

	Startup_In in;
	in.startupType = TPM_SU_CLEAR;
	prettyRC(TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Startup,
		TPM_RH_NULL, nullptr, 0), __func__, ctx);
#endif
}

TPM_RC prettyRC(const TPM_RC rc, const char* callerFunc) {
	if (rc != 0) {
		const char* msg = nullptr;
		const char* submsg = nullptr;
		const char* num = nullptr;

		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("[-] An error occured in %s: %s (%s %s)\n", callerFunc, msg, submsg, num);
	}
	return rc;
}

void prettyRC(const TPM_RC rc, const char* callerFunc, TSS_CONTEXT* ctx) {
	if (rc != 0) {
		const char* msg = nullptr;
		const char* submsg = nullptr;
		const char* num = nullptr;

		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("[-] An error occured in %s: %s (%s %s)\n", callerFunc, msg, submsg, num);
		TSS_Delete(ctx);
		exit(1);
	}
}

/**
 * Creates an ECC restricted decryption primary key with a fixed TPM and fixed parent (i.e., a storage key)
 */
TPM_RC createPrimaryKey(TSS_CONTEXT* ctx,
	const TPMI_RH_HIERARCHY hierarchy,
	const char* parentPassword,
	const char* keyPass,
	const TPM2B_DIGEST* policyDigest,
	CreatePrimary_Out* out)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	CreatePrimary_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.primaryHandle = hierarchy;
	in.inSensitive.sensitive.data.t.size = 0;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.objectAttributes.val = 0;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	in.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_SIGN;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	in.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.objectAttributes.val &= ~0;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
	in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	in.inPublic.publicArea.unique.rsa.t.size = 0;

	if (keyPass == nullptr) {
		in.inSensitive.sensitive.userAuth.t.size = 0;
	}
	else {
		prettyRC(TSS_TPM2B_StringCopy(&in.inSensitive.sensitive.userAuth.b,
			keyPass, sizeof(TPMU_HA)), __func__);
	}
	if (policyDigest == nullptr)
		in.inPublic.publicArea.authPolicy.t.size = 0;
	else {
		in.inPublic.publicArea.authPolicy = *policyDigest;
	}

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_CreatePrimary,
		sessionHandle0, parentPassword, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_CreatePrimary", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return prettyRC(rc, __func__);
}

/**
 * Creates an ECC key
 */
Create_Out create(TSS_CONTEXT* ctx,
	const TPM_HANDLE    parentHandle,
	const char*         parentPassword,
	const TPMA_OBJECT   objectAttributes,
	unsigned char*      keyPassword,
	const TPM2B_DIGEST* authPolicy)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	Create_In  in;
	Create_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.inSensitive.sensitive.data.t.size = 0;
	in.parentHandle = parentHandle;
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.objectAttributes = objectAttributes;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	in.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	in.inPublic.publicArea.unique.ecc.y.t.size = 0;

	if (keyPassword == nullptr) {
		in.inSensitive.sensitive.userAuth.t.size = 0;
	}
	else {
		prettyRC(TSS_TPM2B_Create(&in.inSensitive.sensitive.userAuth.b,
			keyPassword, SHA256_DIGEST_SIZE, sizeof(TPMU_HA)), __func__);
	}
	if (authPolicy == nullptr) {
		in.inPublic.publicArea.authPolicy.t.size = 0;
	}
	else {
		in.inPublic.publicArea.authPolicy = *authPolicy;
	}

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Create,
		sessionHandle0, parentPassword, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_Create", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

TPM_RC evictControl(TSS_CONTEXT* ctx,
	const TPMI_RH_PROVISION  auth,
	const TPMI_DH_OBJECT     objectHandle,
	const TPMI_DH_PERSISTENT persistentHandle)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	EvictControl_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.auth = auth;
	in.objectHandle = objectHandle;
	in.persistentHandle = persistentHandle;

	TPM_RC rc = TSS_Execute(ctx,
		NULL,
		(COMMAND_PARAMETERS*)&in,
		NULL,
		TPM_CC_EvictControl,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_EvictControl", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return rc;
}

Load_Out load(TSS_CONTEXT* ctx,
	const TPMI_DH_OBJECT parentHandle,
	const char* parentPassword,
	const Create_Out& sealedKey)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	Load_In  in;
	Load_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.inPrivate = sealedKey.outPrivate;
	in.inPublic = sealedKey.outPublic;
	in.parentHandle = parentHandle;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Load,
		sessionHandle0, parentPassword, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_Load", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

LoadExternal_Out loadExternal(TSS_CONTEXT* ctx,
	const TPMI_RH_HIERARCHY hierarchy,
	const TPM2B_SENSITIVE*  inPrivate,
	const TPM2B_PUBLIC*     inPublic)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	LoadExternal_In  in;
	LoadExternal_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.hierarchy = hierarchy;
	if (inPrivate == nullptr) {
		in.inPrivate.t.size = 0; // default
	}
	else {
		in.inPrivate = *inPrivate;
	}
	in.inPublic = *inPublic;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_LoadExternal,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_LoadExternal", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

CertifyCreation_Out certifyCreation(TSS_CONTEXT* ctx,
	const TPMI_DH_OBJECT       objectHandle,
	const TPMI_DH_OBJECT       signHandle,
	const TPM2B_DIGEST* creationHash,
	const TPMT_TK_CREATION* creationTicket,
	const char* keyPassword,
	const TPMI_SH_AUTH_SESSION sessionHandle0,
	const unsigned int         sessionAttributes0,
	const TPMI_SH_AUTH_SESSION sessionHandle1,
	const unsigned int         sessionAttributes1,
	const TPMI_SH_AUTH_SESSION sessionHandle2,
	const unsigned int         sessionAttributes2)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	CertifyCreation_In  in;
	CertifyCreation_Out out;

	in.objectHandle = objectHandle;
	in.signHandle = signHandle;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	in.qualifyingData.t.size = 0;
	in.creationHash = *creationHash;
	in.creationTicket = *creationTicket;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_CertifyCreation,
		sessionHandle0, keyPassword, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_CertifyCreation", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

TPMT_SIGNATURE sign(TSS_CONTEXT* ctx,
	const TPM2B_DIGEST* digest,
	const TPMI_DH_OBJECT       keyHandle,
	const TPMT_TK_HASHCHECK* validation,
	const TPMI_SH_AUTH_SESSION sessionHandle0,
	const unsigned int         sessionAttributes0)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	Sign_In  in;
	Sign_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.keyHandle = keyHandle;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
	in.digest = *digest;

	if (validation != nullptr) {
		in.validation = *validation;
	}
	else {
		in.validation.tag = TPM_ST_HASHCHECK;
		in.validation.hierarchy = TPM_RH_NULL;
		in.validation.digest.t.size = 0;
	}

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Sign,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_Sign", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out.signature;
}

TPMT_TK_VERIFIED verifySignature(TSS_CONTEXT* ctx,
	const TPM2B_DIGEST*   digest,
	const TPMI_DH_OBJECT  keyHandle,
	const TPMT_SIGNATURE* signature)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	VerifySignature_In  in;
	VerifySignature_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.digest = *digest;
	in.keyHandle = keyHandle;
	in.signature = *signature;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_VerifySignature,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_VerifySignature", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out.validation;
}

TPM_RC policyTicket(TSS_CONTEXT* ctx,
	const TPM2B_NONCE*   policyRef,
	const TPMI_SH_POLICY policySession,
	const TPM2B_NAME     authName,
	const TPMT_TK_AUTH   ticket,
	const TPM2B_TIMEOUT  timeout)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	PolicyTicket_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authName = authName;
	in.cpHashA.b.size = 0;
	in.policySession = policySession;
	in.ticket = ticket;
	in.timeout = timeout;

	if (policyRef == nullptr) {
		in.policyRef.b.size = 0; // default empty buffer
	}
	else {
		in.policyRef = *policyRef;
	}

	TPM_RC rc = TSS_Execute(ctx,
		NULL,
		(COMMAND_PARAMETERS*)&in,
		NULL,
		TPM_CC_PolicyTicket,
		sessionHandle0, NULL, sessionAttributes0,
		sessionHandle1, NULL, sessionAttributes1,
		sessionHandle2, NULL, sessionAttributes2,
		TPM_RH_NULL, NULL, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_PolicyTicket", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return prettyRC(rc, __func__);
}

TPM_RC policyAuthorize(TSS_CONTEXT* ctx,
	const TPMI_SH_POLICY    policySession,
	const TPM2B_DIGEST*     approvedPolicy,
	const TPM2B_NONCE*      policyRef,
	const TPM2B_NAME        keySign,
	const TPMT_TK_VERIFIED* checkTicket)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	PolicyAuthorize_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.policySession = policySession;
	in.keySign = keySign;

	if (approvedPolicy == nullptr) {
		in.approvedPolicy.b.size = 0;
	}
	else {
		in.approvedPolicy = *approvedPolicy;
	}
	if (policyRef == nullptr) {
		in.policyRef.b.size = 0; // default empty buffer
	}
	else {
		in.policyRef = *policyRef;
	}
	if (checkTicket == nullptr) {
		in.checkTicket.tag = TPM_ST_VERIFIED;
		in.checkTicket.digest.b.size = 0;
		in.checkTicket.hierarchy = TPM_RH_NULL;
	}
	else {
		in.checkTicket = *checkTicket;
	}

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_PolicyAuthorize,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_PolicyAuthorize", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return prettyRC(rc, __func__);
}

PolicySigned_Out policySigned(TSS_CONTEXT* ctx,
	const TPMT_SIGNATURE* auth,
	const TPMI_DH_OBJECT       authObject,
	const TPM2B_DIGEST* cpHashA,
	const INT32                expiration,
	const TPM2B_NONCE* nonceTPM,
	const TPM2B_NONCE* policyRef,
	const TPMI_SH_POLICY       policySession)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	PolicySigned_In  in;
	PolicySigned_Out out;

	in.authObject = authObject;
	in.expiration = expiration;
	in.policySession = policySession;

	if (auth == nullptr) {
		in.auth.sigAlg = TPM_ALG_ECDSA;
		in.auth.signature.ecdsa.hash = TPM_ALG_SHA256;
		in.auth.signature.ecdsa.signatureR.b.size = 0;
		in.auth.signature.ecdsa.signatureS.b.size = 0;
	}
	else {
		in.auth = *auth; // signature
	}
	if (cpHashA == nullptr) {
		in.cpHashA.b.size = 0;
	}
	else {
		in.cpHashA = *cpHashA;
	}
	if (nonceTPM == nullptr) {
		in.nonceTPM.b.size = 0;
	}
	else {
		in.nonceTPM = *nonceTPM;
	}
	if (policyRef == nullptr) {
		in.policyRef.b.size = 0;
	}
	else {
		in.policyRef = *policyRef;
	}

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_PolicySigned,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_PolicySigned", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

void policyNv(TSS_CONTEXT* ctx,
	const TPMI_RH_NV_AUTH      authHandle,
	const TPMI_RH_NV_INDEX     nvIndex,
	const UINT16               offset,
	const TPM2B_OPERAND        operandB,
	const TPM_EO               operation,
	const TPMI_SH_POLICY       policySession,
	const TPMI_SH_AUTH_SESSION sessionHandle0,
	const unsigned int         sessionAttributes0)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	PolicyNV_In in;

	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;
	in.nvIndex = nvIndex;
	in.offset = offset;
	in.operandB = operandB;
	in.operation = operation;
	in.policySession = policySession;

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_PolicyNV,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_PolicyNV", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

TPM_RC startAuthSession(TSS_CONTEXT* ctx, const TPM_SE sessionType, StartAuthSession_Out* out) {
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	StartAuthSession_In    in;
	StartAuthSession_Extra extra;

	in.tpmKey = TPM_RH_NULL;
	in.bind = TPM_RH_NULL;
	in.authHash = TPM_ALG_SHA256;
	in.sessionType = sessionType;
	in.encryptedSalt.b.size = 0;
	in.nonceCaller.t.size = 0;
	in.symmetric.algorithm = TPM_ALG_XOR;
	in.symmetric.keyBits.xorr = TPM_ALG_SHA256;
	in.symmetric.mode.sym = TPM_ALG_NULL;
	extra.bindPassword = nullptr;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)out,
		(COMMAND_PARAMETERS*)&in,
		(EXTRA_PARAMETERS*)&extra,
		TPM_CC_StartAuthSession,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_StartAuthSession", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	return prettyRC(rc, __func__);
}

void flushContext(TSS_CONTEXT* ctx, const TPMI_DH_CONTEXT flushHandle) {
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	FlushContext_In in;

	in.flushHandle = flushHandle;

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_FlushContext,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_FlushContext", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

void nvDefineSpace(TSS_CONTEXT* ctx,
	const TPMI_RH_PROVISION authHandle,
	const TPMI_RH_NV_INDEX  nvIndex,
	const TPMI_ALG_HASH     nameAlg,
	const TPMA_NV           attributes,
	const UINT16            dataSize,
	const TPM2B_AUTH* auth,
	const TPM2B_DIGEST* authPolicy)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	NV_DefineSpace_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;
	in.publicInfo.nvPublic.nvIndex = nvIndex;
	in.publicInfo.nvPublic.nameAlg = nameAlg;
	in.publicInfo.nvPublic.attributes = attributes;
	in.publicInfo.nvPublic.dataSize = dataSize;
	if (auth == nullptr) {
		in.auth.b.size = 0;
	}
	else {
		in.auth = *auth; // nvPassword
	}
	if (authPolicy == nullptr) {
		in.publicInfo.nvPublic.authPolicy.t.size = 0;
	}
	else {
		in.publicInfo.nvPublic.authPolicy = *authPolicy;
	}

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_NV_DefineSpace,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_NV_DefineSpace", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

void nvUndefineSpace(TSS_CONTEXT* ctx,
	const TPMI_RH_PROVISION authHandle,
	const TPMI_RH_NV_INDEX  nvIndex)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	NV_UndefineSpace_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;
	in.nvIndex = nvIndex;

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_NV_UndefineSpace,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_NV_UndefineSpace", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

void nvExtend(TSS_CONTEXT* ctx,
	const TPMI_RH_PROVISION    authHandle,
	const TPM2B_MAX_NV_BUFFER* data,
	const TPMI_RH_NV_INDEX     nvIndex,
	const TPMI_SH_AUTH_SESSION sessionHandle0,
	const unsigned int         sessionAttributes0,
	const TPMI_SH_AUTH_SESSION sessionHandle1,
	const unsigned int         sessionAttributes1)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	NV_Extend_In in;

	// TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	// TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	// unsigned int sessionAttributes0 = 0;
	// unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;
	in.data = *data;
	in.nvIndex = nvIndex;

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_NV_Extend,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_NV_Extend", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

NV_Certify_Out nvCertify(TSS_CONTEXT* ctx,
	const TPMI_RH_NV_AUTH  authHandle,
	const TPMI_RH_NV_INDEX nvIndex,
	const UINT16           offset,
	const TPMI_DH_OBJECT   signHandle,
	const UINT16           size)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	NV_Certify_In  in;
	NV_Certify_Out out;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
	in.nvIndex = nvIndex;
	in.offset = offset;
	in.qualifyingData.t.size = 0;
	in.signHandle = signHandle;
	in.size = size;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_NV_Certify,
		sessionHandle0, nullptr, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_NV_Certify", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}

void clear(TSS_CONTEXT* ctx,
	const TPMI_RH_CLEAR authHandle,
	const char* authPassword)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	Clear_In in;

	TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
	TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
	TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
	unsigned int sessionAttributes0 = 0;
	unsigned int sessionAttributes1 = 0;
	unsigned int sessionAttributes2 = 0;

	in.authHandle = authHandle;

	TPM_RC rc = TSS_Execute(ctx,
		nullptr,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Clear,
		sessionHandle0, authPassword, sessionAttributes0,
		sessionHandle1, nullptr, sessionAttributes1,
		sessionHandle2, nullptr, sessionAttributes2,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_Clear", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);
}

TPM2B_NAME getNameFromPublic(const TPMT_PUBLIC* publicKey, const TPMS_NV_PUBLIC* publicNv) {
	TPM2B_NAME     objectName;
	TPM2B_TEMPLATE marshaled;
	TPMT_HA        name;
	uint16_t       tmpWritten = 0;
	uint32_t       tmpSize    = sizeof(marshaled.t.buffer);
	BYTE*          tmpBuffer  = marshaled.t.buffer;

	// marshal publicArea through tmpBuffer into marshaled buffer
	if (publicKey != nullptr) {
		name.hashAlg = publicKey->nameAlg;
		prettyRC(TSS_TPMT_PUBLIC_Marshalu(publicKey, 
					&tmpWritten, 
					&tmpBuffer, 
					&tmpSize),
                    __func__);
	} else if (publicNv != nullptr) {
		name.hashAlg = publicNv->nameAlg;
		prettyRC(TSS_TPMS_NV_PUBLIC_Marshalu(publicNv, 
					&tmpWritten, 
					&tmpBuffer, 
					&tmpSize),
                    __func__);

	} else {
		objectName.b.size = 0;
		return objectName;
	}
	marshaled.t.size = tmpWritten;

	// generate digest over marshaled buffer
	prettyRC(TSS_Hash_Generate(&name, 
				marshaled.t.size, 
				marshaled.t.buffer, 0, nullptr),
                __func__);

	// extract object name from digest
	objectName.b.buffer[0] = name.hashAlg >> 8;
	objectName.b.buffer[1] = name.hashAlg & 0xff;
	memcpy(&objectName.b.buffer[2], name.digest.tssmax, TSS_GetDigestSize(name.hashAlg));
	objectName.b.size = TSS_GetDigestSize(name.hashAlg)+2;

	return objectName;
}

Hash_Out hash(TSS_CONTEXT* ctx,
	const TPM2B_MAX_BUFFER  data,
	const TPMI_ALG_HASH     hashAlg,
	const TPMI_RH_HIERARCHY hierarchy)
{
#ifdef ENABLE_TIMINGS
	auto t1 = Clock::now();
#endif

	Hash_In  in;
	Hash_Out out;

	in.data = data;
	in.hashAlg = hashAlg;
	in.hierarchy = hierarchy;

	TPM_RC rc = TSS_Execute(ctx,
		(RESPONSE_PARAMETERS*)&out,
		(COMMAND_PARAMETERS*)&in,
		nullptr,
		TPM_CC_Hash,
		TPM_RH_NULL, nullptr, 0);

#ifdef ENABLE_TIMINGS
	auto t2 = Clock::now();
	writeTiming("TPM2_Hash", (double)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count() / 1000000);
#endif

	prettyRC(rc, __func__);

	return out;
}
