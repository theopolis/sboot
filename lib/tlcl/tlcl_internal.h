/* Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef TPM_LITE_TLCL_INTERNAL_H_
#define TPM_LITE_TLCL_INTERNAL_H_

/*
 * These numbers derive from adding the sizes of command fields as shown in the
 * TPM commands manual.
 */
#define kTpmRequestHeaderLength 10
#define kTpmResponseHeaderLength 10
#define kTpmReadInfoLength 12
#define kEncAuthLength 20
#define kPcrDigestLength 20
#define kWriteInfoLength 12
#define kNvDataPublicPermissionsOffset 60

#define TPM_MAX_BUFF_SIZE              4096
#define TPM_HASH_SIZE                  20
#define TPM_NONCE_SIZE                 20
#define TPM_PCR_MASK_SIZE			   2

#define TPM_U16_SIZE                   2
#define TPM_U32_SIZE                   4

#define TPM_MAX_PCR_INFO_SIZE ( (TPM_HASH_SIZE * 2) + TPM_U16_SIZE + TPM_PCR_MASK_SIZE )

/*
 * Conversion functions.  ToTpmTYPE puts a value of type TYPE into a TPM
 * command buffer.  FromTpmTYPE gets a value of type TYPE from a TPM command
 * buffer into a variable.
 */
__attribute__((unused))
static inline void ToTpmUint32(uint8_t *buffer, uint32_t x) {
  buffer[0] = (uint8_t)(x >> 24);
  buffer[1] = (uint8_t)((x >> 16) & 0xff);
  buffer[2] = (uint8_t)((x >> 8) & 0xff);
  buffer[3] = (uint8_t)(x & 0xff);
}

/*
 * See comment for above function.
 */
__attribute__((unused))
static inline void FromTpmUint32(const uint8_t *buffer, uint32_t *x) {
  *x = ((buffer[0] << 24) |
        (buffer[1] << 16) |
        (buffer[2] << 8) |
        buffer[3]);
}

/*
 * See comment for above function.
 */
__attribute__((unused))
static inline void ToTpmUint16(uint8_t *buffer, uint16_t x) {
  buffer[0] = (uint8_t)(x >> 8);
  buffer[1] = (uint8_t)(x & 0xff);
}

/*
 * See comment for above function.
 */
__attribute__((unused))
static inline void FromTpmUint16(const uint8_t *buffer, uint16_t *x) {
  *x = (buffer[0] << 8) | buffer[1];
}

/* The following HMAC functions are defined in tlcl_hmac */

/* Validate the HMAC for an AUTH1 or AUTH2 TPM response
 * response - pointer to response buffer
 * command - the 4byte command code generating the TPM reponse
 * nonceOdd - pointer to TPM_NONCE_SIZE byte array used in the request HMAC
 * key, keySize - the key used in the request HMAC
 * ... - a variable length set of argument pairs (length, offset)
 *   they are an offset and length referring to the TPM response buffer
 *   the last pair must be 0, 0.
 */
uint32_t TSS_CheckHMAC(const uint8_t *response, uint32_t command,
	const uint8_t *nonceOdd,
	const uint8_t *key, uint32_t keySize, const uint8_t *key2, uint32_t keySize2, ...);

uint32_t TSS_AuthHMAC(uint8_t *digest,
	const uint8_t *key, uint32_t keySize, const uint8_t *nonce1, const uint8_t *nonce2,
	uint8_t authBool, ...);


#endif  /* TPM_LITE_TLCL_INTERNAL_H_ */
