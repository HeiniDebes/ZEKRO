#include "prover.h"

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

bool verifyLak(TPMT_SIGNATURE signature, 
    TPM2B_ATTEST       certifyInfo,
    const TPM2B_PUBLIC lakPub, 
    const TPM2B_PUBLIC signingKeyPub,
    const TPM2B_DIGEST policyDigest,
    const TPMA_OBJECT  objectAttributes);
bool verifyNvPcr(const TPMS_NV_PUBLIC expected,
    TPMT_SIGNATURE       signature, 
    TPM2B_ATTEST         certifyInfo,
    const TPM2B_PUBLIC   signingKeyPub,
    const unsigned char* expectedVal);

int main(int argc, char *argv[]) {

    TSS_CONTEXT* ctx = nullptr;
#ifdef DEBUG_TSS
    prettyRC(TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "2"), __func__);
#else
	prettyRC(TSS_SetProperty(nullptr, TPM_TRACE_LEVEL, "1"), __func__);
#endif
    prettyRC(TSS_Create(&ctx), __func__);
    boot(ctx);

    // orchestrator's storage key
	CreatePrimary_Out storageKey;
	createPrimaryKey(ctx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

    // orchestrator's signing key
	Create_Out signingKey;
    TPMA_OBJECT objectAttributes;
    objectAttributes.val = (TPMA_OBJECT_NODA | TPMA_OBJECT_SENSITIVEDATAORIGIN 
            | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN)
            & ~TPMA_OBJECT_ADMINWITHPOLICY & ~TPMA_OBJECT_DECRYPT 
            & ~TPMA_OBJECT_RESTRICTED;
    signingKey = create(ctx, storageKey.objectHandle, nullptr, objectAttributes, nullptr, nullptr);

    flushContext(ctx, storageKey.objectHandle);

	TPM2B_NAME orchestratorSigningKeyName = getNameFromPublic(&signingKey.outPublic.publicArea, nullptr);

	/////////////////////////////////////////////////////////
	// initialize prover node with knowledge about the orchestrator's public key
	TPM2B_DIGEST ID;
	ID.b.size = SHA256_DIGEST_SIZE;
	memset(ID.b.buffer, 8, SHA256_DIGEST_SIZE); // prover node's ID
    Prover prover = Prover(ctx, orchestratorSigningKeyName, signingKey.outPublic);
	prover.id = ID;

	/////////////////////////////////////////////////////////
	// prepare prover's LAK template and authorization policy
	unsigned char ccPolicyAuthorize[4] = { 0x00, 0x00, 0x01, 0x6a }; // TPM_CC_PolicyAuthorize

	TPM2B_DIGEST authPol;
	authPol.b.size = SHA256_DIGEST_SIZE;
	authPol.t.size = SHA256_DIGEST_SIZE;
	memset(authPol.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

	// policyDigest' = H(policyDigest || CC || authName)
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, authPol.b.buffer, authPol.b.size);
	SHA256_Update(&sha256, ccPolicyAuthorize, 4);
	SHA256_Update(&sha256, orchestratorSigningKeyName.b.buffer, orchestratorSigningKeyName.b.size);
	SHA256_Final(authPol.b.buffer, &sha256);

	// policyDigest' = H(policyDigest || ref)
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, authPol.b.buffer, authPol.b.size);
	SHA256_Update(&sha256, ID.b.buffer, ID.b.size); // set node's ID as the node's LAK's authPol's policy reference
	SHA256_Final(authPol.b.buffer, &sha256);

	// the LAK's object attributes (essentially making it a restricted signing key)
	TPMA_OBJECT lakObjectAttributes;
	lakObjectAttributes.val = (TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY | TPMA_OBJECT_SIGN | TPMA_OBJECT_RESTRICTED)
		& ~TPMA_OBJECT_USERWITHAUTH & ~TPMA_OBJECT_DECRYPT;

	/////////////////////////////////////////////////////////
	// ask prover to create its LAK certified by IAK
    CertifyCreation_Out lakCert = prover.createLak(lakObjectAttributes, &authPol);

    // verify prover's LAK based on its IAK
	if (!verifyLak(lakCert.signature,
				lakCert.certifyInfo, 
				prover.mLakPublic, 
				prover.mIakPublic,
				authPol, 
				lakObjectAttributes)) {
		printf("[-] An error occured in %s: prover's LAK is not OK.\n", __func__);
		return 1;
	}

	/////////////////////////////////////////////////////////
	// prepare TEE's NV index
	TPMA_NV nvObjectAttributes;
	nvObjectAttributes.val = TPMA_NVA_AUTHREAD | TPMA_NVA_POLICYWRITE // TPMA_NVA_AUTHWRITE
		| TPMA_NVA_PPREAD | TPMA_NVA_OWNERREAD | TPMA_NVA_NO_DA
		| TPMA_NVA_ORDERLY | TPMA_NVA_EXTEND | TPMA_NVA_WRITEALL
		| TPMA_NVA_PLATFORMCREATE; // | TPMA_NVA_POLICY_DELETE;

	unsigned char ccPolicySigned[4] = { 0x00, 0x00, 0x01, 0x60 }; // TPM_CC_PolicySigned

	authPol.b.size = SHA256_DIGEST_SIZE;
	memset(authPol.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

	TPM2B_NAME teeSigningKeyName = getNameFromPublic(&prover.mTeeSigningKeyPublic.publicArea, nullptr);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, authPol.b.buffer, authPol.b.size);
	SHA256_Update(&sha256, ccPolicySigned, 4);
	SHA256_Update(&sha256, teeSigningKeyName.b.buffer, teeSigningKeyName.b.size);
	SHA256_Final(authPol.b.buffer, &sha256);

	TPM2B_DIGEST policyRef;
	policyRef.b.size = 0;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, authPol.b.buffer, authPol.b.size);
	SHA256_Update(&sha256, policyRef.b.buffer, policyRef.b.size);
	SHA256_Final(authPol.b.buffer, &sha256);

	TPMI_RH_NV_INDEX idx = 0x01001500;

	TPM2B_MAX_NV_BUFFER iv;
	memset(iv.b.buffer, 0, SHA256_DIGEST_SIZE);
	iv.b.size = SHA256_DIGEST_SIZE;

	// ask prover to create its TEE's NV PCR
    NV_Certify_Out nvPcrCert = prover.createNvPcr(idx, nvObjectAttributes, &authPol, &iv);

	// orchestrator verifies the NV PCR certificate
	// calculate expected initial NV PCR value
	unsigned char expectedNvPcrVal[SHA256_DIGEST_SIZE];
	memset(expectedNvPcrVal, 0, SHA256_DIGEST_SIZE);
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, expectedNvPcrVal, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, expectedNvPcrVal, SHA256_DIGEST_SIZE);
	SHA256_Final(expectedNvPcrVal, &sha256);

	TPMS_NV_PUBLIC expected; // the expected NV PCR name
	expected.attributes = nvObjectAttributes;
	expected.attributes.val = expected.attributes.val | TPMA_NVA_WRITTEN;
	expected.authPolicy = authPol;
	expected.dataSize = SHA256_DIGEST_SIZE;
	expected.nameAlg = TPM_ALG_SHA256;
	expected.nvIndex = idx;

	TPM2B_NAME nvPcrName = getNameFromPublic(nullptr, &expected);
	
	if (!verifyNvPcr(
		expected,
		nvPcrCert.signature,
		nvPcrCert.certifyInfo,
		prover.mIakPublic,
		expectedNvPcrVal)) { 
		printf("[-] An error occured in %s: the TEE's NV PCR was not created correctly.\n", __func__);
		return 1;
	}

	/////////////////////////////////////////////////////////
	// orchestrator approves a policy for prover to use its LAK
	unsigned char ccPolicyNv[4] = { 0x00, 0x00 ,0x01, 0x49 }; // TPM_CC_PolicyNV

	TPM2B_DIGEST cid; // current configuration identifier
	cid.b.size = SHA256_DIGEST_SIZE;
	memset(cid.b.buffer, 6, SHA256_DIGEST_SIZE); // for demonstration purposes, we just set it to some value

	TPM2B_DIGEST aPol;
	aPol.b.size = SHA256_DIGEST_SIZE;
	memset(aPol.b.buffer, 0, SHA256_DIGEST_SIZE); // starts with zero digest

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, aPol.b.buffer, aPol.b.size);
	SHA256_Update(&sha256, ccPolicySigned, 4);
	SHA256_Update(&sha256, orchestratorSigningKeyName.b.buffer, orchestratorSigningKeyName.b.size);
	SHA256_Final(aPol.b.buffer, &sha256);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, aPol.b.buffer, aPol.b.size);
	SHA256_Update(&sha256, cid.b.buffer, cid.b.size);
	SHA256_Final(aPol.b.buffer, &sha256);

	// add PolicyNV to policyDigest
	// for NV_Extend, the args are: H(operandB.buffer || offset || operation)
	TPM2B_DIGEST args;
	unsigned char offset[2] = { 0x00, 0x00 };
	unsigned char operation[2] = { 0x00, 0x00 }; // equals

	// the expected digest of the prover's configuration
	TPM2B_DIGEST newMeasurement;
	newMeasurement.b.size = SHA256_DIGEST_SIZE;
	memset(newMeasurement.b.buffer, 1, SHA256_DIGEST_SIZE);

	// simulate the effect of extending the new measurement to the TEE's NV PCR
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, expectedNvPcrVal, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, newMeasurement.b.buffer, newMeasurement.b.size);
	SHA256_Final(expectedNvPcrVal, &sha256); // H(old value || new value)

	// assert the expected NV PCR value
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, expectedNvPcrVal, SHA256_DIGEST_SIZE);
	SHA256_Update(&sha256, offset, 2);
	SHA256_Update(&sha256, operation, 2);
	SHA256_Final(args.b.buffer, &sha256);
	args.b.size = SHA256_DIGEST_SIZE;

	// policyDigest' = H(policyDigest || TPM_CC_PolicyNV || args || nvIndex->name)
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, aPol.b.buffer, aPol.b.size);
	SHA256_Update(&sha256, ccPolicyNv, sizeof(TPM_CC));
	SHA256_Update(&sha256, args.b.buffer, args.b.size);
	SHA256_Update(&sha256, nvPcrName.b.buffer, nvPcrName.b.size);
	SHA256_Final(aPol.b.buffer, &sha256);

	// orchestrator signs an authorization hash over the approved policy and a reference to the prover node's ID
	TPM2B_DIGEST aHash; // H(policyDigest || ref)
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, aPol.b.buffer, aPol.b.size);
	SHA256_Update(&sha256, ID.b.buffer, ID.b.size);
	SHA256_Final(aHash.t.buffer, &sha256);
	aHash.b.size = SHA256_DIGEST_SIZE;

	// orchestrator's storage key
	createPrimaryKey(ctx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

	Load_Out signingKeyLoaded;
    signingKeyLoaded = load(ctx, storageKey.objectHandle, nullptr, signingKey);

	TPMT_SIGNATURE aHashSignature = sign(ctx, &aHash, signingKeyLoaded.objectHandle, nullptr, TPM_RS_PW, 0);

    flushContext(ctx, signingKeyLoaded.objectHandle);
    flushContext(ctx, storageKey.objectHandle);

	// orchestrator gives prover newly approved policy and requests it to measure its configuration into the TEE's NV PCR
    prover.update(&aPol, &aHashSignature, &aHash); // for demonstration purposes we don't send the path to the configuration

	/////////////////////////////////////////////////////////
	// orchestrator approves a new lease to the prover
    TPM2B_NONCE nonceTPM = prover.startSession();

	// orchestrator signs a lease
	PolicySigned_In in;
	in.nonceTPM = nonceTPM; // limit to specific TPM
	in.policyRef = cid; // reference current configuration identifier
	in.cpHashA.b.size = 0; // not limited to a specific command (policy already requires specific PolicyNV)
	in.cpHashA.t.size = 0; // not limited to a specific command (policy already requires specific PolicyNV)
	in.expiration = -50; // 15 seconds until it expires (depends on type of TPM)

	int32_t expirationNbo = htonl(in.expiration);

	// calculate the digest from the 4 components according to the TPM spec Part 3.
	// aHash (authHash) = HauthAlg(nonceTPM || expiration || cpHashA || policyRef)	(13)
	//TPM2B_DIGEST aHash;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &in.nonceTPM.b.buffer, in.nonceTPM.b.size);
	SHA256_Update(&sha256, &expirationNbo, sizeof(int32_t));
	SHA256_Update(&sha256, &in.cpHashA.b.buffer, in.cpHashA.b.size);
	SHA256_Update(&sha256, &in.policyRef.b.buffer, in.policyRef.b.size);
	SHA256_Final(aHash.t.buffer, &sha256);
	aHash.b.size = SHA256_DIGEST_SIZE;

	// orchestrator's storage key
	createPrimaryKey(ctx, TPM_RH_ENDORSEMENT, nullptr, nullptr, nullptr, &storageKey);

    signingKeyLoaded = load(ctx, storageKey.objectHandle, nullptr, signingKey);

	aHashSignature = sign(ctx, &aHash, signingKeyLoaded.objectHandle, nullptr, TPM_RS_PW, 0);

    flushContext(ctx, signingKeyLoaded.objectHandle);
    flushContext(ctx, storageKey.objectHandle);

	// give lease to prover node
    prover.lease(&aHashSignature, in.expiration, &cid);

	/////////////////////////////////////////////////////////
	// Oblivious Remote Attestation

	// generate nonce
	unsigned char nonce[SHA256_DIGEST_SIZE];
	RAND_bytes(nonce, SHA256_DIGEST_SIZE);

	// copy the nonce into a digest structure
	TPM2B_DIGEST nonceDigest;
	memcpy(&nonceDigest.t.buffer, nonce, SHA256_DIGEST_SIZE);
	nonceDigest.t.size = SHA256_DIGEST_SIZE;

	// attest the prover
    TPMT_SIGNATURE signature = prover.attest(nonceDigest);

	// since the prover will hash the nonce using its TPM before signing it using its restricted LAK signing key, we must also hash it before verifying the signature
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &nonceDigest.t.buffer, nonceDigest.t.size);
	SHA256_Final(nonce, &sha256);

	// verify that the prover presented a valid signature over the hashed nonce using its LAK
	EVP_PKEY* containerpk_evp = nullptr;
	TPM_RC rc = prettyRC(convertEcPublicToEvpPubKey(&containerpk_evp, &prover.mLakPublic.publicArea.unique.ecc), __func__);
	if (rc != 0) {
		return false;
	}
	rc = prettyRC(verifyEcSignatureFromEvpPubKey(nonce, SHA256_DIGEST_SIZE, &signature, containerpk_evp), __func__);
	if (rc != 0) {
		return false;
	}

#ifdef VERBOSE
	printf("[+] Success.\n");
#endif

	return 0;
}


bool verifyLak(TPMT_SIGNATURE signature, 
    TPM2B_ATTEST       certifyInfo,
    const TPM2B_PUBLIC lakPub, 
    const TPM2B_PUBLIC signingKeyPub, 
    const TPM2B_DIGEST policyDigest,
    const TPMA_OBJECT  objectAttributes)
{
	TPMS_ATTEST attestData;
	BYTE*       tmpBuffer = certifyInfo.b.buffer;
	uint32_t    tmpSize   = certifyInfo.b.size;

	// unmarshal certifyInfo through tmpBuffer into attestData
	prettyRC(TSS_TPMS_ATTEST_Unmarshalu(&attestData, 
				&tmpBuffer, 
				&tmpSize), 
                __func__);

	if (attestData.magic != TPM_GENERATED_VALUE) {
		printf("[-] An error occured in %s: object not created by TPM\n", __func__);
		return false;
	}

	if (lakPub.publicArea.objectAttributes.val 
		!= objectAttributes.val) {
		printf("[-] An error occured in %s: objectAttributes mismatch\n", __func__);
		return false;
	}

	// check if the AK is bound to the expected authorization policy digest
	if (memcmp(policyDigest.b.buffer, 
				lakPub.publicArea.authPolicy.b.buffer, 
				policyDigest.b.size) != 0) {
		printf("[-] An error occured in %s: policyDigest mismatch\n", __func__);
		return false;
	}

	// calculate name from public area
	TPM2B_NAME objectName = getNameFromPublic(&lakPub.publicArea, nullptr);

	// check if name of object is reflected in the attestation key's certificate
	if (memcmp(attestData.attested.creation.objectName.b.buffer, 
				objectName.b.buffer, 
				SHA256_DIGEST_SIZE + 2) != 0) {
		printf("[-] An error occured in %s: objectName mismatch\n", __func__);
		return false;
	}

	TPMT_HA tmpHashAgile;	
	tmpHashAgile.hashAlg = lakPub.publicArea.nameAlg;
	prettyRC(TSS_Hash_Generate(&tmpHashAgile, 
				certifyInfo.b.size, 
				certifyInfo.b.buffer, 0, nullptr),
                __func__);

	EVP_PKEY* evpPkey = nullptr;
	convertEcPublicToEvpPubKey(&evpPkey, &signingKeyPub.publicArea.unique.ecc);

	// check if the signature over certifyInfo is legitimate
	if (verifyEcSignatureFromEvpPubKey((unsigned char*)&tmpHashAgile.digest, 
				TSS_GetDigestSize(TPM_ALG_SHA256), 
				&signature, 
				evpPkey) != 0) {
		printf("[-] An error occured in %s: illegitimate signature\n", __func__);
		return false;
	}

	return TRUE;
}

bool verifyNvPcr(const TPMS_NV_PUBLIC expected,
				TPMT_SIGNATURE       signature, 
				TPM2B_ATTEST         certifyInfo, 
				const TPM2B_PUBLIC   signingKeyPublic,
				const unsigned char* expectedVal)
{
	TPMS_ATTEST attestData;
	BYTE*       tmpBuffer = certifyInfo.b.buffer;
	uint32_t    tmpSize   = certifyInfo.b.size;

	// unmarshal certifyInfo through tmpBuffer into attestData
	prettyRC(TSS_TPMS_ATTEST_Unmarshalu(&attestData, 
				&tmpBuffer, 
				&tmpSize),
                __func__);

	if (attestData.magic != TPM_GENERATED_VALUE) {
		printf("[-] An error occured in %s: object not created by TPM\n", __func__);
		return false;
	}

	if (memcmp(attestData.attested.nv.nvContents.b.buffer, expectedVal, 
		SHA256_DIGEST_SIZE) != 0) {
		printf("[-] An error occured in %s: NV PCR contents mismatch\n", __func__);
		return false;		
	}

	// compute expected name
	TPM2B_NAME name = getNameFromPublic(nullptr, &expected);

	// check if name of object is same in certificate and NV public section
	if (memcmp(name.b.buffer, 
				attestData.attested.creation.objectName.b.buffer, 
				SHA256_DIGEST_SIZE + 2) != 0) {
		printf("[-] An error occured in %s: objectName mismatch\n", __func__);
		return false;
	}

	TPMT_HA tmpHashAgile;
	tmpHashAgile.hashAlg = expected.nameAlg;
	prettyRC(TSS_Hash_Generate(&tmpHashAgile, 
				certifyInfo.b.size, 
				certifyInfo.b.buffer, 0, nullptr),
                __func__);

	EVP_PKEY* evpPkey = nullptr;
	convertEcPublicToEvpPubKey(&evpPkey, &signingKeyPublic.publicArea.unique.ecc);

	// check if the signature over certifyInfo is legitimate
	if (verifyEcSignatureFromEvpPubKey((unsigned char*)&tmpHashAgile.digest, 
				TSS_GetDigestSize(TPM_ALG_SHA256), 
				&signature, 
				evpPkey) != 0) {
		printf("[-] An error occured in %s: illegitimate signature\n", __func__);
		return false;
	}

	return TRUE;
}
