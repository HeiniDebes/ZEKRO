#include <openssl/hmac.h>
#include "prover.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

Prover::Prover(TSS_CONTEXT* ctx, TPM2B_NAME orchestratorSigningKeyName, TPM2B_PUBLIC orchestratorSigningKeyPublic) 
	: mCtx(ctx), mOrchestratorSigningKeyName(orchestratorSigningKeyName), mOrchestratorSigningKeyPublic(orchestratorSigningKeyPublic)
{
	// prover's storage key
	CreatePrimary_Out storageKey;
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	// prover has an Initial Attestation Key (IAK)
	TPM2B_DIGEST policyDigest;
	policyDigest.b.size = SHA256_DIGEST_SIZE;
	memset(policyDigest.b.buffer, 0, SHA256_DIGEST_SIZE);
    TPMA_OBJECT iakObjectAttributes;
    iakObjectAttributes.val = (TPMA_OBJECT_NODA | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN | TPMA_OBJECT_RESTRICTED) 
		& ~TPMA_OBJECT_DECRYPT; // restricted signing key
	this->iak = create(this->mCtx, storageKey.objectHandle, nullptr, iakObjectAttributes, nullptr, &policyDigest);

	this->mIakPublic = iak.outPublic;

	// prover's TEE has an initial signing key
    TPMA_OBJECT teeObjectAttributes;
    teeObjectAttributes.val = (TPMA_OBJECT_NODA | TPMA_OBJECT_SENSITIVEDATAORIGIN 
            | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN)
            & ~TPMA_OBJECT_ADMINWITHPOLICY & ~TPMA_OBJECT_DECRYPT 
            & ~TPMA_OBJECT_RESTRICTED;
    this->teeSigningKey = create(this->mCtx, storageKey.objectHandle, nullptr, teeObjectAttributes, nullptr, nullptr);

	this->mTeeSigningKeyPublic = this->teeSigningKey.outPublic;

	flushContext(this->mCtx, storageKey.objectHandle);
}

Prover::~Prover() {
	nvUndefineSpace(this->mCtx, TPM_RH_PLATFORM, this->mpcr.idx);
}

CertifyCreation_Out Prover::createLak(const TPMA_OBJECT objectAttributes, const TPM2B_DIGEST* authPol) {
	// prover's storage key
	CreatePrimary_Out storageKey;
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	// create and load LAK
	this->lak = create(this->mCtx, storageKey.objectHandle, nullptr, objectAttributes, nullptr, authPol);
	Load_Out lakLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->lak);

	this->mLakPublic = this->lak.outPublic;

	Load_Out iakLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->iak);

	// prover certifies the LAK using its IAK
	CertifyCreation_Out cert = certifyCreation(this->mCtx,
					lakLoaded.objectHandle, 
					iakLoaded.objectHandle,
					&this->lak.creationHash, 
					&this->lak.creationTicket, 
					nullptr,
					TPM_RS_PW, 0,
					TPM_RH_NULL, 0,
					TPM_RH_NULL, 0);

	flushContext(this->mCtx, lakLoaded.objectHandle);
    flushContext(this->mCtx, iakLoaded.objectHandle);
	flushContext(this->mCtx, storageKey.objectHandle);

	return cert;
}

NV_Certify_Out Prover::createNvPcr(TPMI_RH_NV_INDEX idx, TPMA_NV objectAttributes, const TPM2B_DIGEST* authPol, const TPM2B_MAX_NV_BUFFER* iv) {
	// prover creates its TEE*s NV PCR
	nvDefineSpace(this->mCtx, TPM_RH_PLATFORM, idx, TPM_ALG_SHA256, objectAttributes, SHA256_DIGEST_SIZE, nullptr, authPol);

	this->mpcr.idx = idx;

	// prover starts a session
	StartAuthSession_Out sessionOut;
	startAuthSession(this->mCtx, TPM_SE_POLICY, &sessionOut);

	// TEE signs an authorization to extend the iv into the NV PCR
	PolicySigned_In in;
	in.nonceTPM = sessionOut.nonceTPM; // limit to specific TPM
	in.policyRef.b.size = 0;
	in.expiration = 0; // expire immediately

	// limit cpHashA to the prover executing the NV_Extend with the correct TEE measurement
	// for NV_Extend, the parameters are: dataLength + digest
	unsigned char dataLength[2];
	unsigned char parameters[2 + SHA256_DIGEST_SIZE];
	dataLength[1] = (SHA256_DIGEST_SIZE >> 0) & 0xff;
	dataLength[0] = (SHA256_DIGEST_SIZE >> 8) & 0xff;
	memcpy(&parameters, dataLength, 2);
	memcpy(&parameters[2], iv->b.buffer, iv->b.size);

	TPMS_NV_PUBLIC expected; // the expected NV PCR name
	expected.attributes = objectAttributes;
	expected.attributes.val = expected.attributes.val;
	expected.authPolicy = *authPol;
	expected.dataSize = SHA256_DIGEST_SIZE;
	expected.nameAlg = TPM_ALG_SHA256;
	expected.nvIndex = idx;

	// compute expected name
	this->mpcr.name = getNameFromPublic(nullptr, &expected);

	unsigned char ccNvExtend[4] = { 0x00, 0x00, 0x01, 0x36 }; // TPM_CC_NV_Extend

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, ccNvExtend, 4);
	// NV index name twice since it is used for the authHandle and nvIndex
	SHA256_Update(&sha256, this->mpcr.name.b.buffer, this->mpcr.name.b.size);
	SHA256_Update(&sha256, this->mpcr.name.b.buffer, this->mpcr.name.b.size);
	SHA256_Update(&sha256, parameters, 2 + SHA256_DIGEST_SIZE);
	SHA256_Final(in.cpHashA.t.buffer, &sha256);
	in.cpHashA.t.size = SHA256_DIGEST_SIZE;
	in.cpHashA.b.size = SHA256_DIGEST_SIZE;

	// calculate the digest from the 4 components according to the TPM spec Part 3.
	// aHash (authHash) = HauthAlg(nonceTPM || expiration || cpHashA || policyRef)	(13)
	TPM2B_DIGEST aHash;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &in.nonceTPM.b.buffer, in.nonceTPM.b.size);
	SHA256_Update(&sha256, &in.expiration, sizeof(UINT32));
	SHA256_Update(&sha256, &in.cpHashA.b.buffer, in.cpHashA.b.size);
	SHA256_Update(&sha256, &in.policyRef.b.buffer, in.policyRef.b.size);
	SHA256_Final(aHash.t.buffer, &sha256);
	aHash.b.size = SHA256_DIGEST_SIZE;

	// prover's storage key
	CreatePrimary_Out storageKey;
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	Load_Out teeSigningKeyLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->teeSigningKey);

	TPMT_SIGNATURE aHashSignature = sign(this->mCtx, &aHash, teeSigningKeyLoaded.objectHandle, nullptr, TPM_RS_PW, 0);

	// prover tries to satisfy the TEE's policy to run the nv extend command and then certify the NV PCR
	policySigned(this->mCtx,
		&aHashSignature,
		teeSigningKeyLoaded.objectHandle,
		&in.cpHashA,
		in.expiration,
		&in.nonceTPM,
		nullptr,
		sessionOut.sessionHandle);

	flushContext(this->mCtx, teeSigningKeyLoaded.objectHandle); // flush before calling NV_Extend to reduce internal processing time on HW TPM
	flushContext(this->mCtx, storageKey.objectHandle); // flush before calling NV_Extend to reduce internal processing time on HW TPM

	nvExtend(this->mCtx, idx, iv, idx, sessionOut.sessionHandle, 0, TPM_RH_NULL, 0);

	// prover updates its local mock PCR
	unsigned char initial[SHA256_DIGEST_SIZE];
	memset(initial, 0, SHA256_DIGEST_SIZE);
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, initial, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, iv->b.buffer, iv->b.size);
	SHA256_Final(this->mpcr.val, &sha256);

	// recreate storage key
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);
	// load IAK
	Load_Out iakLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->iak);

	// prover certifies the TEE's NV PCR using its IAK
	NV_Certify_Out cert = nvCertify(this->mCtx, TPM_RH_PLATFORM, idx, 0, iakLoaded.objectHandle, SHA256_DIGEST_SIZE);

	flushContext(this->mCtx, iakLoaded.objectHandle);
	flushContext(this->mCtx, storageKey.objectHandle);

	expected.attributes.val = expected.attributes.val | TPMA_NVA_WRITTEN;
	// recompute NV PCR name since it now also has the WRITTEN attribute
	this->mpcr.name = getNameFromPublic(nullptr, &expected);

	return cert;
}

void Prover::update(const TPM2B_DIGEST* aPol, const TPMT_SIGNATURE* aHashSignature, const TPM2B_DIGEST* aHash) {
	this->aPol = *aPol;

	// verify signature
	// load public part of orchestrator's signing key into TPM storage
	LoadExternal_Out orchestratorSigningKeyPublicLoaded = loadExternal(this->mCtx, 
		TPM_RH_OWNER, 
		nullptr, 
		&this->mOrchestratorSigningKeyPublic);
	this->mTicket = verifySignature(this->mCtx,
		aHash,
		orchestratorSigningKeyPublicLoaded.objectHandle,
		aHashSignature);
	if (this->mTicket.tag != TPM_ST_VERIFIED) {
		printf("lease signature not ok\n");
	}

	flushContext(this->mCtx, orchestratorSigningKeyPublicLoaded.objectHandle);

	// prover starts session to extend NV PCR
	StartAuthSession_Out sessionOut;
	startAuthSession(this->mCtx, TPM_SE_POLICY, &sessionOut);

	// for demonstration purposes we consider a static measurement of the prover's configuration (this should be done using a tracer)
	TPM2B_DIGEST newMeasurement;
	newMeasurement.b.size = SHA256_DIGEST_SIZE;
	memset(newMeasurement.b.buffer, 1, SHA256_DIGEST_SIZE);

	// TEE sign an authorization hash to allow the prover to extend a measurement into the NV PCR
	PolicySigned_In in;
	in.nonceTPM = sessionOut.nonceTPM; // limit to specific TPM
	in.policyRef.b.size = 0;
	in.expiration = 0; // expire immediately

	// limit cpHashA to the prover executing the NV_Extend with the correct TEE measurement (updateDigest)
	// for NV_Extend, the parameters are: dataLength + digest
	unsigned char dataLength[2];
	unsigned char parameters[2 + SHA256_DIGEST_SIZE];
	dataLength[1] = (SHA256_DIGEST_SIZE >> 0) & 0xff;
	dataLength[0] = (SHA256_DIGEST_SIZE >> 8) & 0xff;
	memcpy(&parameters, dataLength, 2);
	memcpy(&parameters[2], newMeasurement.b.buffer, newMeasurement.b.size);

	unsigned char ccNvExtend[4] = { 0x00, 0x00, 0x01, 0x36 }; // TPM_CC_NV_Extend

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, ccNvExtend, 4);
	// NV index name twice since it is used for the authHandle and nvIndex
	SHA256_Update(&sha256, this->mpcr.name.b.buffer, this->mpcr.name.b.size);
	SHA256_Update(&sha256, this->mpcr.name.b.buffer, this->mpcr.name.b.size);
	SHA256_Update(&sha256, parameters, 2 + SHA256_DIGEST_SIZE);
	SHA256_Final(in.cpHashA.t.buffer, &sha256);
	in.cpHashA.t.size = SHA256_DIGEST_SIZE;
	in.cpHashA.b.size = SHA256_DIGEST_SIZE;

	// calculate the digest from the 4 components according to the TPM spec Part 3.
	// aHash (authHash) = HauthAlg(nonceTPM || expiration || cpHashA || policyRef)	(13)
	TPM2B_DIGEST aHashTee;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &in.nonceTPM.b.buffer, in.nonceTPM.b.size);
	SHA256_Update(&sha256, &in.expiration, sizeof(UINT32));
	SHA256_Update(&sha256, &in.cpHashA.b.buffer, in.cpHashA.b.size);
	SHA256_Update(&sha256, &in.policyRef.b.buffer, in.policyRef.b.size);
	SHA256_Final(aHashTee.t.buffer, &sha256);
	aHashTee.b.size = SHA256_DIGEST_SIZE;

	// prover's storage key
	CreatePrimary_Out storageKey;
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	Load_Out teeSigningKeyLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->teeSigningKey);

	TPMT_SIGNATURE aHashSignatureTee = sign(this->mCtx, &aHashTee, teeSigningKeyLoaded.objectHandle, nullptr, TPM_RS_PW, 0);

	// prover tries to run the nv extend command with the measurement
	policySigned(this->mCtx,
		&aHashSignatureTee,
		teeSigningKeyLoaded.objectHandle,
		&in.cpHashA,
		in.expiration,
		&in.nonceTPM,
		nullptr,
		sessionOut.sessionHandle);

	flushContext(this->mCtx, teeSigningKeyLoaded.objectHandle);
	flushContext(this->mCtx, storageKey.objectHandle);

	TPM2B_MAX_NV_BUFFER extendVal;
	memcpy(extendVal.b.buffer, newMeasurement.b.buffer, SHA256_DIGEST_SIZE);
	extendVal.b.size = SHA256_DIGEST_SIZE;
	nvExtend(this->mCtx, this->mpcr.idx, &extendVal, this->mpcr.idx, sessionOut.sessionHandle, 0, TPM_RH_NULL, 0);

	// prover updates its local mock PCR
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, this->mpcr.val, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, newMeasurement.b.buffer, newMeasurement.b.size);
	SHA256_Final(this->mpcr.val, &sha256);
}

TPM2B_NONCE Prover::startSession() {
	// prover starts a session for getting a lease from the orchestrator
	startAuthSession(this->mCtx, TPM_SE_POLICY, &leaseSession);
	return leaseSession.nonceTPM;
}

void Prover::lease(const TPMT_SIGNATURE* aHashSignature, INT32 exp, const TPM2B_DIGEST* cid) {
	// load public part of orchestrator's signing key into TPM storage
	LoadExternal_Out orchestratorSigningKeyPublicLoaded = loadExternal(this->mCtx, 
		TPM_RH_OWNER, 
		nullptr, 
		&this->mOrchestratorSigningKeyPublic);

	// prover gets ticket
	this->mTicketLease = policySigned(this->mCtx,
		aHashSignature,
		orchestratorSigningKeyPublicLoaded.objectHandle,
		nullptr,
		exp,
		&leaseSession.nonceTPM,
		cid,
		leaseSession.sessionHandle);

	flushContext(this->mCtx, leaseSession.sessionHandle);
	flushContext(this->mCtx, orchestratorSigningKeyPublicLoaded.objectHandle);

	this->cid = *cid;
}

TPMT_SIGNATURE Prover::attest(TPM2B_DIGEST nonce) {
	StartAuthSession_Out sessionOut;
	startAuthSession(this->mCtx, TPM_SE_POLICY, &sessionOut);

	policyTicket(this->mCtx, &this->cid, sessionOut.sessionHandle, this->mOrchestratorSigningKeyName, this->mTicketLease.policyTicket, this->mTicketLease.timeout);

	TPM2B_OPERAND operandB;
	memcpy(operandB.b.buffer, this->mpcr.val, SHA256_DIGEST_SIZE);
	operandB.b.size = SHA256_DIGEST_SIZE;

	policyNv(this->mCtx, this->mpcr.idx, this->mpcr.idx, 0, operandB, 0, sessionOut.sessionHandle, TPM_RS_PW, 0);

	policyAuthorize(this->mCtx,
		sessionOut.sessionHandle,
		&this->aPol,
		&this->id,
		this->mOrchestratorSigningKeyName,
		&this->mTicket);

	// prover's storage key (should preferably be stored in persistent storage using Evict)
	CreatePrimary_Out storageKey;
	createPrimaryKey(this->mCtx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	// Because the LAK is a restricted signing key, the TPM will only sign the nonce if it was generated by the TPM.
	// Thus, to sign the nonce, the prover first hashes the nonce using the TPM, and then signs the TPM-generated hash
	TPM2B_MAX_BUFFER data;
	memcpy(data.b.buffer, nonce.b.buffer, SHA256_DIGEST_SIZE);
	data.b.size = SHA256_DIGEST_SIZE;
	Hash_Out nonceHash = hash(this->mCtx, data, TPM_ALG_SHA256, TPM_RH_PLATFORM);

	// load the LAK into TPM memory
	Load_Out lakLoaded = load(this->mCtx, storageKey.objectHandle, nullptr, this->lak);

	// attempt to sign nonce using LAK
	TPMT_SIGNATURE signature = sign(this->mCtx, &nonceHash.outHash, lakLoaded.objectHandle, &nonceHash.validation, sessionOut.sessionHandle, 1);

	flushContext(this->mCtx, lakLoaded.objectHandle);
	flushContext(this->mCtx, storageKey.objectHandle);
	flushContext(this->mCtx, sessionOut.sessionHandle);

	return signature;
}
