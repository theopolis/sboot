/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* TPM Lightweight Command Library.
 *
 * A low-level library for interfacing to TPM hardware or an emulator.
 */

#ifndef TPM_LITE_TLCL_H_
#define TPM_LITE_TLCL_H_

#include <tpm.h>
#include <common.h>
#include <tss_constants.h>


/*****************************************************************************/
/* Functions implemented in tlcl.c */

/* Needed for oiaposap */
uint32_t TlclSendReceive(const uint8_t* request, uint8_t* response, int max_length);
uint32_t Send(const uint8_t* command);

/* Call this first.  Returns 0 if success, nonzero if error.
 */
__attribute__((unused))
uint32_t TlclLibInit(void);

/* Call this on shutdown.  Returns 0 if success, nonzero if error.
 */
uint32_t TlclLibClose(void);

/* Logs to stdout.  Arguments like printf.
 */
void TlclLog(char* format, ...);

/* Sets the log level.  0 is quietest.
 */
void TlclSetLogLevel(int level);

/* Sends a TPM_Startup(ST_CLEAR).  The TPM error code is returned (0
 * for success).
 */
uint32_t TlclStartup(void);

/* Save the TPM state.  Normally done by the kernel before a suspend, included
 * here for tests.  The TPM error code is returned (0 for success).
 */
uint32_t TlclSaveState(void);

/* Resumes by sending a TPM_Startup(ST_STATE).  The TPM error code is returned
 * (0 for success).
 */
uint32_t TlclResume(void);

/* Runs the self test.  Note---this is synchronous.  To run this in parallel
 * with other firmware, use ContinueSelfTest.  The TPM error code is returned.
 */
uint32_t TlclSelfTestFull(void);

/* Runs the self test in the background.
 */
uint32_t TlclContinueSelfTest(void);

/* Defines a space with permission [perm].  [index] is the index for the space,
 * [size] the usable data size.  The TPM error code is returned.
 */
uint32_t TlclDefineSpace(uint32_t index, uint32_t perm, uint32_t size);

/* Writes [length] bytes of [data] to space at [index].  The TPM error code is
 * returned.
 */
uint32_t TlclWrite(uint32_t index, const void* data, uint32_t length);

/* Reads [length] bytes from space at [index] into [data].  The TPM error code
 * is returned.
 */
uint32_t TlclRead(uint32_t index, void* data, uint32_t length);

/* Reads PCR at [index] into [data].  [length] must be TPM_PCR_DIGEST or
 * larger. The TPM error code is returned.
 */
uint32_t TlclPCRRead(uint32_t index, void* data, uint32_t length);

/* Write-locks space at [index].  The TPM error code is returned.
 */
uint32_t TlclWriteLock(uint32_t index);

/* Read-locks space at [index].  The TPM error code is returned.
 */
uint32_t TlclReadLock(uint32_t index);

/* Asserts physical presence in software.  The TPM error code is returned.
 */
uint32_t TlclAssertPhysicalPresence(void);

/* Enables the physical presence command.  The TPM error code is returned.
 */
uint32_t TlclPhysicalPresenceCMDEnable(void);

/* Finalizes the physical presence settings: sofware PP is enabled, hardware PP
 * is disabled, and the lifetime lock is set.  The TPM error code is returned.
 */
uint32_t TlclFinalizePhysicalPresence(void);

/* Turns off physical presence and locks it off until next reboot.  The TPM
 * error code is returned.
 */
uint32_t TlclLockPhysicalPresence(void);

/* Sets the nvLocked bit.  The TPM error code is returned.
 */
uint32_t TlclSetNvLocked(void);

/* Returns 1 if the TPM is owned, 0 otherwise.
 */
int TlclIsOwned(void);

/* Issues a ForceClear.  The TPM error code is returned.
 */
uint32_t TlclForceClear(void);

/* Issues a PhysicalEnable.  The TPM error code is returned.
 */
uint32_t TlclSetEnable(void);

/* Issues a PhysicalDisable.  The TPM error code is returned.
 */
uint32_t TlclClearEnable(void);

/* Issues a SetDeactivated.  Pass 0 to activate.  Returns result code.
 */
uint32_t TlclSetDeactivated(uint8_t flag);

/* Gets flags of interest.  Pointers for flags you aren't interested in may
 * be NULL.  The TPM error code is returned.
 */
uint32_t TlclGetFlags(uint8_t* disable, uint8_t* deactivated,
                      uint8_t* nvlocked);

/* Sets the bGlobalLock flag, which only a reboot can clear.  The TPM error
 * code is returned.
 */
uint32_t TlclSetGlobalLock(void);

/* Performs a TPM_Extend.
 */
uint32_t TlclExtend(int pcr_num, const uint8_t* in_digest, uint8_t* out_digest);

/* Gets the permission bits for the NVRAM space with |index|.
 */
uint32_t TlclGetPermissions(uint32_t index, uint32_t* permissions);

/* Gets the entire set of permanent flags.
 */
uint32_t TlclGetPermanentFlags(TPM_PERMANENT_FLAGS* pflags);

/* Gets the entire set of volatile (ST_CLEAR) flags.
 */
uint32_t TlclGetSTClearFlags(TPM_STCLEAR_FLAGS* pflags);

/* Gets ownership flag. The TPM error code is returned.
 */
uint32_t TlclGetOwnership(uint8_t* owned);

/* Requests [length] bytes from TPM RNG to be stored in [data]. Actual
 * number of bytes read is stored in [size]. The TPM error code is returned.
 */
uint32_t TlclGetRandom(uint8_t* data, uint32_t length, uint32_t* size);

/* Resets the TPM, removing loaded keys and opened handles.
 */
uint32_t TlclReset(void);

/* Seal commands */
uint32_t TlclSeal(uint32_t keyHandle, const uint8_t *pcrInfo, uint32_t pcrInfoSize, const uint8_t *keyAuth, const uint8_t *dataAuth, const uint8_t *data, uint32_t dataSize, uint8_t *blob, uint32_t *blobSize);
uint32_t TSS_GenPCRInfo(uint32_t pcrMap, uint8_t *pcrInfo, uint32_t *size);
uint32_t TlclSealPCR(uint32_t keyHandle, uint32_t pcrMap, const uint8_t *keyAuth, const uint8_t *dataAuth, const uint8_t *data, uint32_t dataSize, uint8_t *blob, uint32_t *blobSize);
uint32_t TlclUnseal(uint32_t keyHandle, const uint8_t *keyAuth, const uint8_t *dataAuth, const uint8_t *blob, uint32_t blobSize, uint8_t *rawData, uint32_t *dataSize);

/* Key structures */
typedef struct Tlcl_PublicKeyData {
	uint32_t algorithm;
	uint16_t encscheme;
	uint16_t sigscheme;
	uint32_t keybitlen;
	uint32_t numprimes;
	uint32_t expsize;
	uint8_t exponent[3];
	uint32_t keylength;
	uint8_t modulus[256];
	uint32_t pcrinfolen;
	uint8_t pcrinfo[256];
} Tlcl_PublicKeyData;

typedef struct Tlcl_KeyData {
	uint8_t version[4];
	uint16_t keyusage;
	uint32_t keyflags;
	uint8_t authdatausage;
	Tlcl_PublicKeyData pub;
	uint32_t privkeylen;
	uint8_t encprivkey[1024];
} Tlcl_KeyData;

uint32_t TlclGetCapability(uint32_t capability,
	uint8_t *subCap, uint32_t subCapSize,
	uint8_t *response, uint32_t *responseSize);
uint32_t TlclCreateWrapKey(uint32_t parentKeyHandle, uint8_t *parentKeyAuth,
	uint8_t *keyAuth, uint8_t *migrationAuth,
	Tlcl_KeyData *keyParams, Tlcl_KeyData *key,
	uint8_t *keyBlob, uint32_t *blobSize);

#endif  /* TPM_LITE_TLCL_H_ */
