/*
 * libtpm: OAIP/OSAP routines
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 * tlcl implementation
 * Copyright (C) 2012 V Lab Technologies
 * Author: Teddy Reed
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include <sha1.h>
#include <tlcl.h>

#include "oiaposap.h"
#include "oiaposap_structures.h"

/****************************************************************************
 *
 * Open an OIAP session
 * Object Independent Authorization Protocol, will not work on commands
 * that introduce new AuthData to the TPM
 *
 ****************************************************************************/
uint32_t TSS_OIAPopen(uint32_t *handle, uint8_t *enonce)
{
	struct s_tpm_oiap_open_cmd cmd;
	uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
	uint32_t result;

	debug("TPM: TSS_OIAPopen\n");
	/* check input arguments */
	if (handle == NULL || enonce == NULL) {
		return TPM_E_NULL_ARG;
	}

	memcpy(&cmd, &tpm_oiap_open_cmd, sizeof(cmd));
	result = TlclSendReceive(cmd.buffer, response, sizeof(response));

	if (result == TPM_SUCCESS) {
		FromTpmUint32(response + kTpmResponseHeaderLength, handle);
		memcpy(enonce, response + kTpmResponseHeaderLength + sizeof(uint32_t), TPM_NONCE_SIZE);
	}

	return result;
}

/****************************************************************************/
/*                                                                          */
/* Close an OIAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OIAPclose(uint32_t handle)
{
	return TSS_HANDclose(handle);
}

/****************************************************************************
 *
 * Open an OSAP session
 * Object Specific Authorization Protocol, returned handle must manipulate
 * a single object given as a parameter (can introduce AuthData).
 *                                                                          *
 ****************************************************************************/
uint32_t TSS_OSAPopen(struct tss_osapsess *sess, const uint8_t *key, uint16_t etype,
		      uint32_t evalue)
{
	struct s_tpm_osap_open_cmd cmd;
	uint8_t response[TPM_LARGE_ENOUGH_COMMAND_SIZE];
	uint32_t nonceSize;
	uint32_t result;

	debug("TPM: TSS_OSAPopen\n");
	/* check input arguments */
	if (key == NULL || sess == NULL) {
		return TPM_E_NULL_ARG;
	}

	TlclGetRandom(sess->ononceOSAP, TPM_NONCE_SIZE, &nonceSize);

	memcpy(&cmd, &tpm_osap_open_cmd, sizeof(cmd));
	ToTpmUint16(cmd.buffer + tpm_osap_open_cmd.type, etype);
	ToTpmUint32(cmd.buffer + tpm_osap_open_cmd.value, evalue);
	memcpy(cmd.buffer + tpm_osap_open_cmd.nonce, sess->ononceOSAP, TPM_NONCE_SIZE);

	result = TlclSendReceive(cmd.buffer, response, sizeof(response));

	if (result == TPM_SUCCESS) {
		FromTpmUint32(response + kTpmResponseHeaderLength, &(sess->handle));
		memcpy(sess->enonce, response + kTpmResponseHeaderLength + sizeof(uint32_t), TPM_NONCE_SIZE);
		memcpy(sess->enonceOSAP, response + kTpmResponseHeaderLength + sizeof(uint32_t) + TPM_NONCE_SIZE, TPM_NONCE_SIZE);

		debug("TPM: TSS_OSAPopen success, calculating HMAC\n");
		/*DATA_DEBUG("key", key, TPM_HASH_SIZE);
		DATA_DEBUG("enonceOSAP", sess->enonceOSAP, TPM_NONCE_SIZE);
		DATA_DEBUG("ononceOSAP", sess->ononceOSAP, TPM_NONCE_SIZE);*/

		/* not implemented */
		SHA1_CTX hmac;
		hmac_starts(&hmac, key, TPM_HASH_SIZE);
		hmac_update(&hmac, sess->enonceOSAP, TPM_NONCE_SIZE);
		hmac_update(&hmac, sess->ononceOSAP, TPM_NONCE_SIZE);
		hmac_finish(&hmac, key, TPM_HASH_SIZE, sess->ssecret);
	}

	return result;
}

/****************************************************************************/
/*                                                                          */
/* Close an OSAP session                                                    */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_OSAPclose(struct tss_osapsess *sess)
{
	uint32_t ret;

	if (sess == NULL)
		return TPM_E_NULL_ARG;
	ret = TSS_HANDclose(sess->handle);
	return ret;
}

/****************************************************************************/
/*                                                                          */
/* Terminate the Handle Opened by TPM_OIAPOpen, or TPM_OSAPOpen             */
/*                                                                          */
/****************************************************************************/
uint32_t TSS_HANDclose(uint32_t handle)
{
	struct s_tpm_handle_close_cmd cmd;
	uint32_t result;

	memcpy(&cmd, &tpm_handle_close_cmd, sizeof(cmd));
	ToTpmUint32(cmd.buffer + tpm_handle_close_cmd.handle, handle);

	result = Send(cmd.buffer);
	return result;
}
