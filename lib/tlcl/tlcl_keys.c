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

#include <tlcl.h>
#include "tlcl_internal.h"
#include "oiaposap.h"

uint32_t TlclCreateWrapKey(uint32_t parentKeyHandle, uint8_t *parentKeyAuth,
	uint8_t *keyAuth, uint8_t *migrationAuth,
	Tlcl_KeyData *keyParams, Tlcl_KeyData *key,
	uint8_t *keyBlob, uint32_t *blobSize)
{
	uint32_t result;

	uint8_t command[TPM_MAX_COMMAND_SIZE] = {0x0, 0xc2};
	uint8_t response[TPM_MAX_COMMAND_SIZE];
	uint8_t keyParamBuffer[TPM_MAX_COMMAND_SIZE];
	uint8_t nonceOdd[TPM_NONCE_SIZE];
	uint8_t xorWork[TPM_HASH_SIZE * 2];
	uint8_t xorHash[TPM_HASH_SIZE];
	uint8_t encAuth[TPM_HASH_SIZE], encAuth2[TPM_HASH_SIZE];
	uint8_t authHmacDigest[TPM_HASH_SIZE], pubAuth[TPM_HASH_SIZE];
	struct tss_osapsess sess;
	SHA1_CTX ctx;
	uint16_t keyType;
	uint32_t size, keyParamBufferSize;
	uint32_t i;
	uint8_t c, tpm_hmac_data[TPM_U32_SIZE];

	/* Must provide keyParams, and keyAuth/partentAuth (0's for well-known) */
	if (keyParams == NULL || keyAuth == NULL || parentKeyAuth == NULL) {
		return TPM_E_NULL_ARG;
	}

	/* Only type 1 keys for now */
	keyType = 0x0001;

	/* Add TPM version to keyParams */
	result = TlclGetCapability(0x00000006, NULL, 0, &(keyParams->version[0]), &size);
	if (result != TPM_SUCCESS) {
		return result;
	}

	/* Generate Odd Nonce */
	TlclGetRandom(nonceOdd, TPM_NONCE_SIZE, &size);

	/* Open OSAP session */
	result = TSS_OSAPopen(&sess, parentKeyAuth, keyType, parentKeyHandle);
	if (result != TPM_SUCCESS) {
		return result;
	}

	/* Calculate encrypted authorization value for new key */
	memcpy(xorWork, sess.ssecret, TPM_HASH_SIZE);
	memcpy(xorWork + TPM_HASH_SIZE, sess.enonce, TPM_HASH_SIZE);
	sha1_starts(&ctx);
	sha1_update(&ctx, xorWork, TPM_HASH_SIZE * 2);
	sha1_finish(&ctx, xorHash);

	for (i = 0; i < TPM_HASH_SIZE; ++i) {
		encAuth[i] = xorHash[i] ^ keyAuth[i];
	}

	if (migrationAuth != NULL) {
		/* Calculate encrypted authorization value for migration of new key */
		memcpy(xorWork, sess.ssecret, TPM_HASH_SIZE);
		memcpy(xorWork + TPM_HASH_SIZE, nonceOdd, TPM_HASH_SIZE);
		sha1_starts(&ctx);
		sha1_update(&ctx, xorWork, TPM_HASH_SIZE * 2);
		sha1_finish(&ctx, xorHash);

		for (i = 0; i < TPM_HASH_SIZE; ++i) {
			encAuth2[i] = xorHash[i] ^ migrationAuth[i];
		}
	} else {
		memset(encAuth2, 0, TPM_HASH_SIZE);
	}
	memset(xorWork, 0, TPM_HASH_SIZE * 2);
	memset(xorHash, 0, TPM_HASH_SIZE);

	/* Convert keyParam to command buffer */
	memcpy(keyParamBuffer, keyParams->version, 4);
	ToTpmUint16(keyParamBuffer + 4, keyParams->keyusage);
	ToTpmUint32(keyParamBuffer + 6, keyParams->keyflags);
	memset(keyParamBuffer + 10, keyParams->authdatausage, 1);
	ToTpmUint32(keyParamBuffer + 11, keyParams->pub.algorithm);
	ToTpmUint16(keyParamBuffer + 15, keyParams->pub.encscheme);
	ToTpmUint16(keyParamBuffer + 17, keyParams->pub.sigscheme);
	ToTpmUint32(keyParamBuffer + 19, 12);
	ToTpmUint32(keyParamBuffer + 23, keyParams->pub.keybitlen);
	ToTpmUint32(keyParamBuffer + 27, keyParams->pub.numprimes);
	ToTpmUint32(keyParamBuffer + 31, 0);
	ToTpmUint32(keyParamBuffer + 35, keyParams->pub.pcrinfolen);
	memcpy(keyParamBuffer + 39, keyParams->pub.pcrinfo, keyParams->pub.pcrinfolen);
	ToTpmUint32(keyParamBuffer + 39 + keyParams->pub.pcrinfolen, keyParams->pub.keylength);
	memcpy(keyParamBuffer + 43 + keyParams->pub.pcrinfolen, keyParams->pub.modulus, keyParams->pub.keylength);
	ToTpmUint32(keyParamBuffer + 43 + keyParams->pub.pcrinfolen + keyParams->pub.keylength, keyParams->privkeylen);
	memcpy(keyParamBuffer + 47 + keyParams->pub.pcrinfolen + keyParams->pub.keylength, keyParams->encprivkey, keyParams->privkeylen);
	/* Set keyParam buffer size */
	keyParamBufferSize = 47 + keyParams->pub.pcrinfolen + keyParams->pub.keylength + keyParams->privkeylen;

	debug("keyParamBuffer size: %d\n", keyParamBufferSize);

	/* Calculate authorization HMAC */
	c = 0;
	sha1_starts(&ctx);
	ToTpmUint32(tpm_hmac_data, 0x1f); /* could be 1f */
	sha1_update(&ctx, tpm_hmac_data, TPM_U32_SIZE);
	sha1_update(&ctx, encAuth, TPM_HASH_SIZE);
	sha1_update(&ctx, encAuth2, TPM_HASH_SIZE);
	sha1_update(&ctx, keyParamBuffer, keyParamBufferSize);
	sha1_finish(&ctx, authHmacDigest);
	/*memset(encAuth, 0, TPM_HASH_SIZE);
	memset(encAuth2, 0, TPM_HASH_SIZE);*/

	hmac_starts(&ctx, sess.ssecret, TPM_HASH_SIZE);
	hmac_update(&ctx, authHmacDigest, TPM_HASH_SIZE);
	hmac_update(&ctx, sess.enonce, TPM_NONCE_SIZE);
	hmac_update(&ctx, nonceOdd, TPM_NONCE_SIZE);
	hmac_update(&ctx, &c, 1);
	hmac_finish(&ctx, sess.ssecret, TPM_HASH_SIZE, pubAuth);

	/* Build the command */
	size = 2 + TPM_U32_SIZE * 3 /* size, keyHandle */ + TPM_HASH_SIZE * 2 +
		keyParamBufferSize + TPM_U32_SIZE /* sess.handle */ + TPM_NONCE_SIZE +
		1 + TPM_HASH_SIZE;
	ToTpmUint32(command + 2, size);
	ToTpmUint32(command + 6, 0x1f); /* ordinal */
	ToTpmUint32(command + 10, parentKeyHandle);
	memcpy(command + 14, encAuth, TPM_HASH_SIZE);
	memcpy(command + 14 + TPM_HASH_SIZE, encAuth2, TPM_HASH_SIZE);
	memcpy(command + 14 + TPM_HASH_SIZE * 2, keyParamBuffer, keyParamBufferSize);
	ToTpmUint32(command + 14 + TPM_HASH_SIZE * 2 + keyParamBufferSize, sess.handle);
	memcpy(command + 18 + TPM_HASH_SIZE * 2 + keyParamBufferSize, nonceOdd, TPM_NONCE_SIZE);
	memset(command + 18 + TPM_HASH_SIZE * 2 + keyParamBufferSize + TPM_NONCE_SIZE, c, 1);
	memcpy(command + 19 + TPM_HASH_SIZE * 2 + keyParamBufferSize + TPM_NONCE_SIZE, pubAuth, TPM_HASH_SIZE);

	/* Transmit command, receive response */
	result = TlclSendReceive(command, response, sizeof(response));


	return result;
}

