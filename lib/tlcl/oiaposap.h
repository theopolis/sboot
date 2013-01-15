/*
 * libtpm: oiaposap.h
 *
 * Copyright (C) 2004 IBM Corporation
 * Author: J. Kravitz
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#ifndef OIAPOSAP_H
#define OIAPOSAP_H
#include "tlcl_internal.h"

struct tss_osapsess {
	uint32_t handle;
	uint8_t enonce[TPM_NONCE_SIZE];
	uint8_t enonceOSAP[TPM_NONCE_SIZE];
	uint8_t ononceOSAP[TPM_NONCE_SIZE];
	uint8_t ssecret[TPM_HASH_SIZE];
	uint8_t ononce[TPM_NONCE_SIZE];
};

uint32_t TSS_HANDclose(uint32_t handle);
uint32_t TSS_OIAPopen(uint32_t * handle, uint8_t *enonce);
uint32_t TSS_OIAPclose(uint32_t handle);
uint32_t TSS_OSAPopen(struct tss_osapsess *sess,
	const uint8_t *key, uint16_t etype, uint32_t evalue);
uint32_t TSS_OSAPclose(struct tss_osapsess *sess);

#endif
