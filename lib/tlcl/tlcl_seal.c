/*
 * tlcl: Seal, Unseal
 * Copyright (C) 2012 V Lab Technologies
 * Author: Teddy Reed
 * Based on libtpm by J. Kravitz (IBM) (C) 2004
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include <sha1.h>
#include <malloc.h>

#include <tlcl.h>
#include "tlcl_internal.h"
#include "oiaposap.h"

/* tpm seal/unseal commands */

uint32_t TlclSeal(uint32_t keyHandle,
		const uint8_t *pcrInfo, uint32_t pcrInfoSize,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *data, uint32_t dataSize,
		uint8_t *blob, uint32_t *blobSize)
{
	uint16_t i;
	uint32_t result;
	uint8_t command[TPM_MAX_COMMAND_SIZE] = {0x0, 0xC2};
	uint8_t response[TPM_MAX_COMMAND_SIZE];

	struct tss_osapsess sess;
	uint8_t encAuth[TPM_HASH_SIZE];
	uint8_t pubAuth[TPM_HASH_SIZE];
	uint32_t size, sealInfoSize, encDataSize, storedSize;
	uint8_t nonceOdd[TPM_NONCE_SIZE];

	/* might not use */
	uint8_t xorWork[TPM_HASH_SIZE * 2];
	uint8_t xorHash[TPM_HASH_SIZE];
	SHA1_CTX ctx;

	uint16_t keyType; /* for keyHandle */

	/* TPM (big-endian data) for authentication HMAC */
	uint8_t tpm_hmac_data[TPM_U32_SIZE];
	uint8_t authHmacDigest[TPM_HASH_SIZE];
	uint8_t c;

	/* Input data checking */
	if (data == NULL || blob == NULL) {
		/* Todo: return error */
		return TPM_E_NULL_ARG; /* EINVAL */
	}
	if (pcrInfoSize != 0 && pcrInfo == NULL) {
		/* Todo: return error */
		return TPM_E_NULL_ARG; /* EINVAL */
	}

	if (keyHandle == 0x40000000) {
		keyType = 0x0004;
		debug("TPM: seal using SRK.\n");
	} else {
		keyType = 0x0001;
	}
	/* handle null auth for key and data, for now only use non-null passwords */
	/* assert(keyAuth != NULL && dataAuth != NULL); */

	result = TSS_OSAPopen(&sess, keyAuth, keyType, keyHandle);
	if (result != TPM_SUCCESS) {
		/* This will fail is key does not exist or TPM has not run TakeOwnership. */
		debug("TPM: TSS_OSAPopen failed\n");
		return result;
	}

	/* calculate encrypted authorization value */
	memcpy(xorWork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorWork + TPM_HASH_SIZE, sess.enonce, TPM_HASH_SIZE);
	sha1_starts(&ctx);
	sha1_update(&ctx, xorWork, TPM_HASH_SIZE * 2);
	sha1_finish(&ctx, xorHash);
	memset(xorWork, 0, TPM_HASH_SIZE * 2);

	/* generate odd nonce */
	TlclGetRandom(nonceOdd, TPM_NONCE_SIZE, &size);

	/* encrypt data authorization key, expects dataAuth to be as hash */
	for (i = 0; i < TPM_HASH_SIZE; ++i) {
		encAuth[i] = xorHash[i] ^ dataAuth[i];
	}
	memset(xorHash, 0, TPM_HASH_SIZE);

	/* calculate authorization HMAC */
	c = 0;
	sha1_starts(&ctx);
	ToTpmUint32(tpm_hmac_data, 0x17);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, encAuth, TPM_HASH_SIZE);
	ToTpmUint32(tpm_hmac_data, pcrInfoSize);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	if (pcrInfoSize > 0) {
		/* PCRs */
		sha1_update(&ctx, pcrInfo, pcrInfoSize);
		/* this time include pcrInfo */
	}
	ToTpmUint32(tpm_hmac_data, dataSize);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, data, dataSize);
	sha1_finish(&ctx, authHmacDigest);

	hmac_starts(&ctx, sess.ssecret, TPM_HASH_SIZE);
	hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
	hmac_update(&ctx, sess.enonce, TPM_NONCE_SIZE);
	hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
	hmac_update(&ctx, &c, 1);
	hmac_finish(&ctx, sess.ssecret, TPM_HASH_SIZE, pubAuth);

	/* Build command */
	size = 2 /*tag*/ + 12 /*paramSize,ordinal,keyHandle*/ + TPM_HASH_SIZE /*encAuth*/ +
		pcrInfoSize + 4 /*size included*/ + dataSize + 4 + 4 /*authHandle*/ + TPM_NONCE_SIZE +
		1 /*authSess bool*/ + TPM_HASH_SIZE;
	ToTpmUint32(command + 2, size);
	ToTpmUint32(command + 6, 0x17);
	ToTpmUint32(command + 10, keyHandle);
	memcpy(command + 14, encAuth, TPM_HASH_SIZE);
	ToTpmUint32(command + 14 + TPM_HASH_SIZE, pcrInfoSize);
	if (pcrInfoSize > 0) {
		memcpy(command + 18 + TPM_HASH_SIZE, pcrInfo, pcrInfoSize);
	}
	ToTpmUint32(command + 18 + TPM_HASH_SIZE + pcrInfoSize, dataSize);
	memcpy(command + 22 + TPM_HASH_SIZE + pcrInfoSize, data, dataSize);
	ToTpmUint32(command + 22 + TPM_HASH_SIZE + pcrInfoSize + dataSize, sess.handle);
	memcpy(command + 26 + TPM_HASH_SIZE + pcrInfoSize + dataSize, nonceOdd, TPM_NONCE_SIZE);
	memset(command + 26 + TPM_HASH_SIZE + pcrInfoSize + dataSize + TPM_NONCE_SIZE, 0, 1);
	memcpy(command + 27 + TPM_HASH_SIZE + pcrInfoSize + dataSize + TPM_NONCE_SIZE, pubAuth, TPM_HASH_SIZE);

	/* send command */
	result = TlclSendReceive(command, response, sizeof(response));

	if (result == TPM_SUCCESS) {
		/* first 32bit after the header is the size of return */
		FromTpmUint32(response + kTpmResponseHeaderLength, &size);
		FromTpmUint32(response + kTpmResponseHeaderLength + TPM_U32_SIZE, &sealInfoSize);
		debug("TPM: seal info size: %d\n", sealInfoSize);
		FromTpmUint32(response + kTpmResponseHeaderLength + TPM_U32_SIZE + TPM_U32_SIZE + sealInfoSize, &encDataSize);
		debug("TPM: enc data size: %d\n", encDataSize);
		storedSize = TPM_U32_SIZE * 3 + sealInfoSize + encDataSize;
		debug("TPM: stored size: %d\n", storedSize);

		/* check HMAC */
		result = TSS_CheckHMAC(response, 0x17, nonceOdd, sess.ssecret, TPM_HASH_SIZE, NULL, 0, storedSize, TPM_DATA_OFFSET, 0, 0);

		/* set output param values */
		memcpy(blob, response + kTpmResponseHeaderLength, storedSize);
		*blobSize = storedSize;
	} else {
		/* Todo: check if OSAP is closed upon success */
		TSS_OSAPclose(&sess);
	}

	return result;
}

uint32_t TSS_GenPCRInfo(uint32_t pcrMap, uint8_t *pcrInfo, uint32_t *size)
{
	uint32_t result;

	struct pcrInfo {
		uint8_t selSize[TPM_U16_SIZE]; /* uint16_t */
		uint8_t select[TPM_PCR_MASK_SIZE];
		uint8_t relHash[TPM_HASH_SIZE];
		uint8_t crtHash[TPM_HASH_SIZE];
	} info;

	uint16_t i, j, numRegs;
	uint32_t pcrMapTemp;
	uint8_t *pcrValues, valueSize[TPM_U32_SIZE];
	SHA1_CTX ctx;

	/* must be valid pointers */
	if (pcrInfo == NULL || size == NULL) {
		return TPM_E_NULL_ARG;
	}

	/* build PCR selection matrix */
	pcrMapTemp = pcrMap;
	memset(info.select, 0, TPM_PCR_MASK_SIZE);
	for (i = 0; i < TPM_PCR_MASK_SIZE; ++i) {
		info.select[i] = pcrMapTemp & 0x000000FF;
		pcrMapTemp = pcrMapTemp >> 8;
	}

	/* calculate number of PCR registers requested */
	numRegs = 0;
	pcrMapTemp = pcrMap;
	for (i = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i) {
		if (pcrMapTemp & 1) ++numRegs;
		pcrMapTemp = pcrMapTemp >> 1;
	}

	/* check for 0 registers */
	if (numRegs == 0) {
		*size = 0;
		return 0;
	}

	/* create a matrix of PCR values */
	pcrValues = (uint8_t *) malloc(TPM_HASH_SIZE * numRegs);
	pcrMapTemp = pcrMap;
	for (i = 0, j = 0; i < (TPM_PCR_MASK_SIZE * 8); ++i, pcrMapTemp = pcrMapTemp >> 1) {
		if ((pcrMapTemp & 1) == 0) continue;
		result = TlclPCRRead(i, &(pcrValues[(j * TPM_HASH_SIZE)]), kPcrDigestLength);
		if (result != TPM_SUCCESS) {
			/* todo: print trace */
			return result;
		}
		++j;
	}

	ToTpmUint16(info.selSize, TPM_PCR_MASK_SIZE);
	ToTpmUint32(valueSize, numRegs * TPM_HASH_SIZE);

	/* composite hash of selected PCR values */
	sha1_starts(&ctx);
	sha1_update(&ctx, info.selSize, TPM_U16_SIZE);
	sha1_update(&ctx, info.select, TPM_PCR_MASK_SIZE);
	sha1_update(&ctx, valueSize, TPM_U32_SIZE);
	for (i = 0; i < numRegs; ++i) {
		sha1_update(&ctx, &(pcrValues[(i * TPM_HASH_SIZE)]), TPM_HASH_SIZE);
	}
	sha1_finish(&ctx, info.relHash);
	memcpy(info.crtHash, info.relHash, TPM_HASH_SIZE);

	/* copy to input params */
	memcpy(pcrInfo, &info, sizeof(struct pcrInfo));
	*size = sizeof(struct pcrInfo);

	return TPM_SUCCESS;
}


uint32_t TlclSealPCR(uint32_t keyHandle, uint32_t pcrMap,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *data, uint32_t dataSize,
		uint8_t *blob, uint32_t *blobSize)
{
	uint32_t result;

	uint8_t pcrInfo[TPM_MAX_PCR_INFO_SIZE];
	uint32_t pcrSize;

	result = TSS_GenPCRInfo(pcrMap, pcrInfo, &pcrSize);
	if (result != TPM_SUCCESS) {
		return result;
	}

	return TlclSeal(keyHandle, pcrInfo, pcrSize, keyAuth, dataAuth, data,
		dataSize, blob, blobSize);
}

uint32_t TlclUnseal(uint32_t keyHandle,
		const uint8_t *keyAuth, const uint8_t *dataAuth,
		const uint8_t *blob, uint32_t blobSize,
		uint8_t *rawData, uint32_t *dataSize)
{
	uint32_t result;
	uint8_t command[TPM_MAX_COMMAND_SIZE] = {0x0, 0xC3};
	uint8_t response[TPM_MAX_COMMAND_SIZE];

	uint32_t keyAuthHandle, dataAuthHandle, size;
	uint8_t keyAuthData[TPM_HASH_SIZE], dataAuthData[TPM_HASH_SIZE];
	uint8_t enonceKey[TPM_NONCE_SIZE], enonceData[TPM_NONCE_SIZE];
	uint8_t nonceOdd[TPM_NONCE_SIZE];
	uint8_t authHmacDigest[TPM_HASH_SIZE];
	uint8_t c, offset;
	SHA1_CTX ctx;

	/* used to convert host-endianess to TPM-endianess (big) */
	uint8_t tpm_hmac_data[TPM_U32_SIZE];

	/* check input params */
	if (rawData == NULL || blob == NULL) {
		return TPM_E_NULL_ARG;
	}

	/* Data auth is required, key may not require auth. */
	if (keyAuth != NULL) {
		result = TSS_OIAPopen(&keyAuthHandle, enonceKey);
		if (result != TPM_SUCCESS) {
			return result;
		}
	}
	result = TSS_OIAPopen(&dataAuthHandle, enonceData);
	if (result != TPM_SUCCESS) {
		return result;
	}

	/* generate odd nonce */
	TlclGetRandom(nonceOdd, TPM_NONCE_SIZE, &size);
	/* todo: is it OK to use the same odd nonce? */

	c = 0;
	ToTpmUint32(tpm_hmac_data, 0x18);
	/* calculate key authorization HMAC */
	sha1_starts(&ctx);
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, blob, blobSize);
	sha1_finish(&ctx, authHmacDigest);

	/* Again, key auth may not be required */
	if (keyAuth != NULL) {
		hmac_starts(&ctx, keyAuth, TPM_HASH_SIZE);
		hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
		hmac_update(&ctx, enonceKey, TPM_NONCE_SIZE);
		hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
		hmac_update(&ctx, &c, 1);
		hmac_finish(&ctx, keyAuth, TPM_HASH_SIZE, keyAuthData);
	}

	/* calculate data authorization HMAC */
	hmac_starts(&ctx, dataAuth, TPM_HASH_SIZE);
	hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
	hmac_update(&ctx, enonceData, TPM_NONCE_SIZE);
	hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
	hmac_update(&ctx, &c, 1);
	hmac_finish(&ctx, dataAuth, TPM_HASH_SIZE, dataAuthData);

	/* build command buffer */
	size = 2 /*tag*/ + TPM_U32_SIZE * 3 /*paramSize, ordinal, keyHandle*/ +
		TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE +
		blobSize + TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE;

	if (keyAuth == NULL) {
		size -= (TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE);
		memset(command, 0x00, 1);
		memset(command + 1, 0xc2, 1); /* only 1 authHandle */
	}

	ToTpmUint32(command + 2, size);
	ToTpmUint32(command + 6, 0x18);
	ToTpmUint32(command + 10, keyHandle);

	/* Blob contains flags and size of sealed data */
	memcpy(command + 14, blob, blobSize);

	/* key auth params: handle, nonceOdd, continue_bool, keyAuthHMAC */
	offset = 0;
	if (keyAuth != NULL) {
		ToTpmUint32(command + 14 + blobSize, keyAuthHandle);
		memcpy(command + 18 + blobSize, nonceOdd, TPM_NONCE_SIZE);
		memcpy(command + 18 + blobSize + TPM_NONCE_SIZE, &c, 1);
		memcpy(command + 19 + blobSize + TPM_NONCE_SIZE, keyAuthData, TPM_HASH_SIZE);
		offset += TPM_U32_SIZE + TPM_NONCE_SIZE + 1 + TPM_HASH_SIZE;
	}

	/* data auth params: handle, nonceOdd, continue_bool, dataAuthHMAC */
	ToTpmUint32(command + 14 + blobSize + offset, dataAuthHandle);
	memcpy(command + 18 + blobSize + offset, nonceOdd, TPM_NONCE_SIZE);
	memcpy(command + 18 + blobSize + offset + TPM_NONCE_SIZE , &c, 1);
	memcpy(command + 19 + blobSize + offset + TPM_NONCE_SIZE, dataAuthData, TPM_HASH_SIZE);

	/* send command */
	result = TlclSendReceive(command, response, sizeof(response));

	if (result == TPM_SUCCESS) {
		/* first 32bit after the header is the size of return */
		/* size of returned data blob */
		FromTpmUint32(response + kTpmResponseHeaderLength, dataSize);

		/* check HMAC */
		if (keyAuth != NULL) {
			/* key + data password, AUTH2 */
			result = TSS_CheckHMAC(response, 0x18, nonceOdd,
				keyAuth, TPM_HASH_SIZE, dataAuth, TPM_HASH_SIZE,
				TPM_U32_SIZE, TPM_DATA_OFFSET,
				*dataSize, TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		} else {
			/* data password, AUTH1 */
			result = TSS_CheckHMAC(response, 0x18, nonceOdd,
				dataAuth, TPM_HASH_SIZE, NULL, 0,
				TPM_U32_SIZE, TPM_DATA_OFFSET,
				*dataSize, TPM_DATA_OFFSET + TPM_U32_SIZE, 0, 0);
		}

		/* set output param values */
		memcpy(rawData, response + kTpmResponseHeaderLength + TPM_U32_SIZE, *dataSize);
	} else {
		/* OIAP sessions should close on success */
		if (keyAuth != NULL) {
			TSS_OIAPclose(keyAuthHandle);
		}
		TSS_OIAPclose(dataAuthHandle);
	}

	return result;
}
