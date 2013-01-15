/*
 * libsboot - U-Boot Trusted/Secured Boot implementation.
 * Author: Teddy Reed <teddy@prosauce.org>
 *
 * Sboot depends on libtlcl, a lite TSS based on tlcl from the Chromium Project's vboot.
 * The functions defined in libsboot are implemented in U-boot and optionally in SPL.
 */

#include <common.h>
#include <sha1.h>

#include <sboot.h>

#define	TPM_BASE						0
#define	TPM_INVALID_POSTINIT			(TPM_BASE+38)

/* May turn off physical presence, may allow for a trusted boot instead of secure. */
__attribute__((unused))
uint8_t sboot_finish(void);

#ifndef CONFIG_SBOOT_DISABLE_CONSOLE_EXTEND
/* If SBOOT is extending console commands then it has two options for
 * measurement, as it must consider measuring the act of sealing measurement:
 *   1. Check for the SBOOT seal command, and skip measurement.
 *   2. Always measure the SBOOT seal command before booting.
 * Finally, to preserve automatic booting, the default boot command (and legacy variants)
 * should not be measured.
 */
const char 		*console_measure_exceptions[] = {
	"sboot seal", "boot", "bootd"
};
#endif

/* TPM must be started, enabled, activated, and owned.
 *   If not owned, OSAP will return a key use error.
 */
__attribute__((unused))
uint8_t sboot_seal(const uint8_t *key, uint32_t keySize,
	uint32_t pcrMap, uint16_t nv_index)
{
	uint32_t result;

	uint32_t keyHandle;
	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	uint8_t blob[312];
	uint32_t blobSize;

	/* Max size of key */
	if (keySize > 96) {
		return SBOOT_DATA_ERROR;
	}

	/* Use SRK for encrypting */
	keyHandle = 0x40000000;

	/* default TPM passwords */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);

	TlclLibInit();

	result = TlclSealPCR(keyHandle, pcrMap, keyAuth, dataAuth,
		key, keySize, blob, &blobSize);

	if (result != TPM_SUCCESS) {
		/* problem */
		debug("sboot: Failed to seal.\n");
		return SBOOT_TPM_ERROR;
	}

	debug("sboot: Writing blob to NVRAM: (index=%d).\n", nv_index);

	result = TlclWrite(nv_index, (void *) blob, blobSize);
	debug("sboot: write complete.\n");
	if (result != TPM_SUCCESS) {
		debug("sboot: Failed to write NVRAM.\n");
		return SBOOT_TPM_ERROR;
	}

	debug("sboot: Seal success.\n");
	return 0;
}

__attribute__((unused))
uint8_t sboot_seal_toggle(void)
{
	int result;

	result = setenv("sbootseal", "bootm");
	if (result != 0)
		return SBOOT_DATA_ERROR;
	return SBOOT_SUCCESS;
}

__attribute__((unused))
uint8_t sboot_seal_uboot(void)
{
	uint8_t result;

	uint32_t pcrMap;
	uint8_t key[20];

	/* Create bitmap of PCR registers to seal on */
	pcrMap = 0 + (1 << SBOOT_PCR_UBOOT) + (1 << SBOOT_PCR_CHIPSET_CONFIG);

	memset(key, SBOOT_SEAL_WELL_KNOWN_KEY, 20);
	result = sboot_seal(key, 20, pcrMap, SBOOT_NV_INDEX_SEAL_UBOOT);

	return result;
}

__attribute__((unused))
uint8_t sboot_seal_os(void)
{
	uint8_t result;

	uint32_t pcrMap;
	uint8_t key[20];

	/* Create bitmap of PCR registers to seal on */
	pcrMap = 0 + (1 << SBOOT_PCR_UBOOT) + (1 << SBOOT_PCR_CHIPSET_CONFIG) +
		(1 << SBOOT_PCR_KERNEL);
	/* Only add PCRs if measuring environment and console. */
#ifndef CONFIG_SBOOT_UBOOT_DISABLE_ENV_EXTEND
	pcrMap += (1 << SBOOT_PCR_UBOOT_ENVIRONMENT);
#endif
#ifndef CONFIG_SBOOT_UBOOT_DISABLE_CONSOLE_EXTEND
	pcrMap += (1 << SBOOT_PCR_UBOOT_CONSOLE);
#endif

	memset(key, SBOOT_SEAL_WELL_KNOWN_KEY, 20);
	result = sboot_seal(key, 20, pcrMap, SBOOT_NV_INDEX_SEAL_OS);

	return result;
}

uint8_t sboot_unseal(const uint8_t *sealData, uint32_t sealDataSize,
	uint8_t *unsealData, uint32_t *unsealDataSize)
{
	uint32_t result;

	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	/* Use WK-password for SRK and data */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);
	result = TlclUnseal(0x40000000, keyAuth, dataAuth,
		sealData, sealDataSize, unsealData, unsealDataSize);
	if (result != TPM_SUCCESS) {
		debug("sboot: Failed to unseal data.\n");
		return SBOOT_DATA_ERROR;
	}

	return SBOOT_SUCCESS;
}

uint8_t sboot_init(void)
{
	uint32_t tpm_result;

	TSS_BOOL disabled, deactivated, nvlocked;
	uint8_t pcrCheck[20], pcrDefault[20];
	uint32_t permissions;

	puts("Sboot initializing SRTM\n");

	TlclLibInit();

	tpm_result = TlclStartup();
	if (tpm_result != TPM_SUCCESS && tpm_result != TPM_INVALID_POSTINIT) {
		/* Invalid Postinit is returned if TPM is already started */
		goto error;
	}

	TlclSelfTestFull(); /* Required by some TPMs */
	TlclSetNvLocked(); /* Enforce security controls on NVRAM. */
	TlclGetFlags(&disabled, &deactivated, &nvlocked);

	if (disabled == 1 || deactivated == 1) {
		/* TPM is deactivated or disabled, possibly try to enable/activate */
		/* Todo: SBOOT should return an error notifying the implementor to
		 * configure (enable/activate) their TPM
		 */
		/* Todo: Set enabled and activated, then try again. */
		debug("sboot: The TPM is disabled or deactivated.\n");
		goto error;
	}

	if (nvlocked != 1) {
		/* TPM's NVRAM is not locked, meaning there is no read/write control
		 * enforcement. SBOOT can set GlobalLock, but the Owner should also
		 * be set (which should happen external to SBOOT). If the Owner is set
		 * then the defined NVRAM indexes need to be defined with PPREAD|PPWRITE.
		 */
		debug("sboot: The TPM NVRAM is not locked.\n");
		goto error;
	}

	/* Check PCR values, they should be 0, else they will need to be reset.
	 * A reset can occur via operator authentication or a physical reset.
	 */
	memset(pcrDefault, 0x0, 20);
	tpm_result = TlclPCRRead(SBOOT_PCR_UBOOT, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = TlclPCRRead(SBOOT_PCR_CHIPSET_CONFIG, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: CHIPSET CONFIG PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = TlclPCRRead(SBOOT_PCR_UBOOT_ENVIRONMENT, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT ENVIRONMENT PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = TlclPCRRead(SBOOT_PCR_UBOOT_CONSOLE, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: UBOOT CONSOLE PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}
	tpm_result = TlclPCRRead(SBOOT_PCR_KERNEL, (void *) pcrCheck, 20);
	if (tpm_result != TPM_SUCCESS || memcmp(pcrCheck, pcrDefault, 20) != 0) {
		debug("sboot: KERNEL PCR is unreadable or extended.\n");
		tpm_result = SBOOT_TPM_ERROR;
		goto error;
	}


	/* Check NVRAM indexes and permissions, the permissions must be PPREAD|PPWRITE */
	tpm_result = TlclGetPermissions(SBOOT_NV_INDEX_SEAL_UBOOT, &permissions);
	if (tpm_result != TPM_SUCCESS) {
		debug("sboot: failed to get permissions for NVRAM UBOOT_SEAL (index=%d).\n", SBOOT_NV_INDEX_SEAL_UBOOT);
		goto error;
	}
	if (permissions != (TPM_NV_PER_PPWRITE|TPM_NV_PER_PPREAD)) {
		debug("sboot: NVRAM permissions for UBOOT_SEAL are incorrect (perm=%d).\n", permissions);
		goto error;
	}

	TlclGetPermissions(SBOOT_NV_INDEX_SEAL_OS, &permissions);
	if (tpm_result != TPM_SUCCESS) {
		debug("sboot: Failed to get permissions for NVRAM OS_SEAL (index=%d).\n", SBOOT_NV_INDEX_SEAL_OS);
		goto error;
	}
	if (permissions != (TPM_NV_PER_PPWRITE|TPM_NV_PER_PPREAD)) {
		debug("sboot: NVRAM permissions for OS_SEAL are incorrect (perm=%d).\n", permissions);
		goto error;
	}

	/* Physical presence must match the security controls on NVRAM. */
	tpm_result = TlclAssertPhysicalPresence();
	if (tpm_result != TPM_SUCCESS) {
		debug("sboot: Failed to enable Physical Presence\n");
	}

error:
	if (tpm_result != TPM_SUCCESS) {
		puts("sboot: Failed to initialize TPM\n");
		return SBOOT_TPM_ERROR;
	}

	return SBOOT_SUCCESS;
}

/* Read seal data containing 312 bytes (20byte encrypted hash) from TPM NVRAM.
 * Try to unseal (verifying correct PCR values).
 *
 * If CONFIG_SBOOT_ENFORCE is enabled sboot_check will hang on failure.
 */
uint8_t sboot_check(uint16_t nv_index)
{
	uint32_t result;

	uint32_t unsealDataSize;
	uint8_t sealData[312];
	uint8_t unsealData[20];

	result = TlclRead(nv_index, sealData, 312);
	if (result != TPM_SUCCESS) {
		debug("sboot: failed to read seal data from %d.\n", nv_index);
		return SBOOT_TPM_ERROR;
	}

	/* no need to check unsealed data */
	result = sboot_unseal(sealData, 312, unsealData, &unsealDataSize);
	if (result != SBOOT_SUCCESS) {
		debug("sboot: failed to unseal.\n");
		return SBOOT_DATA_ERROR;
	}

#ifdef CONFIG_SBOOT_ENFORCE
	puts("\n\n(Critical!) System state change detected\n");
	sboot_finish();
	hang();
#endif

	return SBOOT_SUCCESS;
}

__attribute__((unused))
uint8_t sboot_check_os(void)
{
	return sboot_check(SBOOT_NV_INDEX_SEAL_OS);
}

__attribute__((unused))
uint8_t sboot_extend(uint16_t pcr, const uint8_t* in_digest, uint8_t* out_digest)
{
	TlclLibInit();

	if (TlclExtend(pcr, in_digest, out_digest) != TPM_SUCCESS)
		return SBOOT_TPM_ERROR;

	return SBOOT_SUCCESS;
}

#ifndef CONFIG_SBOOT_DISABLE_CONSOLE_EXTEND
__attribute__((unused))
uint8_t sboot_extend_console(const char *buffer, uint32_t max_size)
{
	uint32_t size;
	uint8_t i = 0;

	uint8_t digest[20], out_digest[20];
	SHA1_CTX ctx;

	/* sboot will extend the console up to the max_size given to the command.
	 * It is possible that input validation did not happen on buffer, thus
	 * max_size is an explicit parameter to the memory compare.
	 *
	 * max_size is not used by default, as it is possible the memory
	 * space after the null-terminated buffer was NOT scrubbed.
	 */
	size = (strlen(buffer) < max_size) ? strlen(buffer) : max_size;

	/* Do not seal if command buffer is a measurement exception */
	for (i = 0; i < sizeof(console_measure_exceptions) / sizeof(char *); ++i) {
		if (strlen(console_measure_exceptions[i]) == size &&
			memcmp(console_measure_exceptions[i], console_buffer, size) == 0) {
			return SBOOT_DATA_ERROR;
		}
	}

	debug("sboot: Extending console with \"%s\" (size=%d).\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	return sboot_extend(SBOOT_PCR_UBOOT_CONSOLE, digest, out_digest);
}
#endif

#ifndef CONFIG_SBOOT_DISABLE_ENV_EXTEND
__attribute__((unused))
uint8_t sboot_extend_environment(const char *buffer, uint32_t size)
{
	uint8_t digest[20], out_digest[20];
	SHA1_CTX ctx;

	debug("sboot: Extending env with \"%s\" (size=%d).\n", buffer, size);

	sha1_starts(&ctx); /* could be 1 function, sha1_csum */
	sha1_update(&ctx, (const unsigned char*) buffer, size);
	sha1_finish(&ctx, digest);

	return sboot_extend(SBOOT_PCR_UBOOT_ENVIRONMENT, digest, out_digest);
}
#endif

__attribute__((unused))
uint8_t sboot_extend_os(const uint8_t* start, uint32_t size)
{
	/* uint32_t i; */
	uint8_t digest[20], out_digest[20];
	SHA1_CTX ctx;

	if (size == 0)
		return SBOOT_SUCCESS;

	debug("sboot: Extending OS (addr=%x, size=%d)\n", (uint32_t) start, size);

	sha1_starts(&ctx);
	sha1_update(&ctx, start, size);
	sha1_finish(&ctx, digest);

	return sboot_extend(SBOOT_PCR_KERNEL, digest, out_digest);
}

__attribute__((unused))
uint8_t sboot_lock_pcrs(void)
{
	uint8_t lockNonce[20]; /* should be TPM_NONCE_SIZE */
	uint32_t size;
	uint8_t output[20];

	TlclGetRandom(lockNonce, 20, &size);

	sboot_extend(SBOOT_PCR_UBOOT, lockNonce, output);
	sboot_extend(SBOOT_PCR_CHIPSET_CONFIG, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_ENVIRONMENT, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_CONSOLE, lockNonce, output);
	sboot_extend(SBOOT_PCR_UBOOT_MEMORY, lockNonce, output);
	sboot_extend(SBOOT_PCR_KERNEL, lockNonce, output);
	return SBOOT_SUCCESS;
}

__attribute__((unused))
uint8_t sboot_finish(void)
{
	/* Remove PP, thus locking READ/WRITE to NVRAM. */
	debug("sboot: finished; locking PCRs and Physical Presence.\n");
	sboot_lock_pcrs();
	TlclLockPhysicalPresence();

	return SBOOT_SUCCESS;
}
