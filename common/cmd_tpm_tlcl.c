/* Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Adopted from cros_cmd_tpm_tests.
 */

#include <common.h>
#include <command.h>
#include <environment.h>
#include <tlcl.h>

#include <sha1.h>

/* Prints error and returns on failure */
#define TPM_CHECK(tpm_command) do { \
	uint32_t result; \
	if ((result = (tpm_command)) != TPM_SUCCESS) { \
		printf("TEST FAILED: line %d: " #tpm_command ": 0x%x\n", \
			__LINE__, result); \
		return result; \
	} \
} while (0)

#define INDEX0 0xda70
#define INDEX1 0xda71
#define INDEX2 0xda72
#define INDEX3 0xda73
#define INDEX_INITIALIZED 0xda80

static uint32_t TlclStartupIfNeeded(void) {
	uint32_t result = TlclStartup();
	return result == TPM_E_INVALID_POSTINIT ? TPM_SUCCESS : result;
}

/* u-boot internal timer test
 */

static int test_timer(void)
{
	printf("get_timer(0) = %lu\n", get_timer(0));
	return 0;
}

/* vboot_reference/tests/tpm_lite tests
 */

static int test_early_extend(void)
{
	uint8_t value_in[20];
	uint8_t value_out[20];
	printf("Testing earlyextend ...");
	TlclLibInit();
	TlclStartup();
	TPM_CHECK(TlclContinueSelfTest());
	TPM_CHECK(TlclExtend(1, value_in, value_out));
	printf("done\n");
	return 0;
}

static int test_early_nvram(void)
{
	uint32_t x;
	printf("Testing earlynvram ...");
	TlclLibInit();
	TlclStartup();
	TPM_CHECK(TlclContinueSelfTest());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclRead(INDEX0, (uint8_t*) &x, sizeof(x)));
	printf("done\n");
	return 0;
}

static int test_early_nvram2(void)
{
	uint32_t x;
	printf("Testing earlynvram2 ...");
	TlclLibInit();
	TPM_CHECK(TlclStartup());
	TPM_CHECK(TlclContinueSelfTest());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclWrite(INDEX0, (uint8_t*) &x, sizeof(x)));
	printf("done\n");
	return 0;
}

static int test_enable(void)
{
	uint8_t disable, deactivated;
	printf("Testing enable ...\n");
	TlclLibInit();
	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclSelfTestFull());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclGetFlags(&disable, &deactivated, NULL));
	printf("\tdisable is %d, deactivated is %d\n", disable, deactivated);
	TPM_CHECK(TlclSetEnable());
	TPM_CHECK(TlclSetDeactivated(0));
	TPM_CHECK(TlclGetFlags(&disable, &deactivated, NULL));
	printf("\tdisable is %d, deactivated is %d\n", disable, deactivated);
	if (disable == 1 || deactivated == 1) {
		printf("\tfailed to enable or activate\n");
	}
	printf("\tdone\n");
	return 0;
}

#define reboot() do { \
	printf("\trebooting...\n"); \
	reset_cpu(0); \
} while (0)

static int test_fast_enable(void)
{
	uint8_t disable, deactivated;
	int i;
	printf("Testing fastenable ...\n");
	TlclLibInit();
	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclSelfTestFull());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclGetFlags(&disable, &deactivated, NULL));
	printf("\tdisable is %d, deactivated is %d\n", disable, deactivated);
	for (i = 0; i < 2; i++) {
		TPM_CHECK(TlclForceClear());
		TPM_CHECK(TlclGetFlags(&disable, &deactivated, NULL));
		printf("\tdisable is %d, deactivated is %d\n", disable,
			deactivated);
		assert(disable == 1 && deactivated == 1);
		TPM_CHECK(TlclSetEnable());
		TPM_CHECK(TlclSetDeactivated(0));
		TPM_CHECK(TlclGetFlags(&disable, &deactivated, NULL));
		printf("\tdisable is %d, deactivated is %d\n", disable,
			deactivated);
		assert(disable == 0 && deactivated == 0);
	}
	printf("\tdone\n");
	return 0;
}

static int test_global_lock(void)
{
	uint32_t zero = 0;
	uint32_t result;
	uint32_t x;
	printf("Testing globallock ...\n");
	TlclLibInit();
	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclSelfTestFull());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclRead(INDEX0, (uint8_t*) &x, sizeof(x)));
	TPM_CHECK(TlclWrite(INDEX0, (uint8_t*) &zero, sizeof(uint32_t)));
	TPM_CHECK(TlclRead(INDEX1, (uint8_t*) &x, sizeof(x)));
	TPM_CHECK(TlclWrite(INDEX1, (uint8_t*) &zero, sizeof(uint32_t)));
	TPM_CHECK(TlclSetGlobalLock());
	// Verifies that write to index0 fails.
	x = 1;
	result = TlclWrite(INDEX0, (uint8_t*) &x, sizeof(x));
	assert(result == TPM_E_AREA_LOCKED);
	TPM_CHECK(TlclRead(INDEX0, (uint8_t*) &x, sizeof(x)));
	assert(x == 0);
	// Verifies that write to index1 is still possible.
	x = 2;
	TPM_CHECK(TlclWrite(INDEX1, (uint8_t*) &x, sizeof(x)));
	TPM_CHECK(TlclRead(INDEX1, (uint8_t*) &x, sizeof(x)));
	assert(x == 2);
	// Turns off PP.
	TlclLockPhysicalPresence();
	// Verifies that write to index1 fails.
	x = 3;
	result = TlclWrite(INDEX1, (uint8_t*) &x, sizeof(x));
	assert(result == TPM_E_BAD_PRESENCE);
	TPM_CHECK(TlclRead(INDEX1, (uint8_t*) &x, sizeof(x)));
	assert(x == 2);
	printf("\tdone\n");
	return 0;
}

static int test_lock(void)
{
	printf("Testing lock ...\n");
	TlclLibInit();
	TlclStartup();
	TlclSelfTestFull();
	TlclAssertPhysicalPresence();
	TlclWriteLock(INDEX0);
	printf("\tLocked 0x%x\n", INDEX0);
	printf("\tdone\n");
	return 0;
}

static int test_reset(void)
{
	printf("Testing reset ...\n");
	TlclReset();
	printf("\tdone\n");
	return 0;
}

static void initialize_spaces(void) {
	uint32_t zero = 0;
	uint32_t perm = TPM_NV_PER_WRITE_STCLEAR | TPM_NV_PER_PPWRITE;

	printf("\tInitializing spaces\n");
	TlclSetNvLocked();  /* useful only the first time */
	TlclDefineSpace(INDEX0, perm, 4);
	TlclWrite(INDEX0, (uint8_t *) &zero, 4);
	TlclDefineSpace(INDEX1, perm, 4);
	TlclWrite(INDEX1, (uint8_t *) &zero, 4);
	TlclDefineSpace(INDEX2, perm, 4);
	TlclWrite(INDEX2, (uint8_t *) &zero, 4);
	TlclDefineSpace(INDEX3, perm, 4);
	TlclWrite(INDEX3, (uint8_t *) &zero, 4);
	perm = TPM_NV_PER_READ_STCLEAR | TPM_NV_PER_WRITE_STCLEAR |
		TPM_NV_PER_PPWRITE;
	TlclDefineSpace(INDEX_INITIALIZED, perm, 1);
}


static void enter_recovery_mode(void) {
	printf("entering recovery mode");
	reboot();
}


static int test_readonly(void)
{
	uint8_t c;
	uint32_t index_0, index_1, index_2, index_3;
	int read_0, read_1, read_2, read_3;
	printf("Testing readonly ...\n");
	TlclLibInit();
	TlclStartup();
	TlclSelfTestFull();
	TlclAssertPhysicalPresence();
	/* Checks if initialization has completed by trying to read-lock a space
	 * that's created at the end of initialization.
	 */
	if (TlclRead(INDEX_INITIALIZED, &c, 0) == TPM_E_BADINDEX) {
		/* The initialization did not complete.
		 */
		initialize_spaces();
	}

	/* Checks if spaces are OK or messed up.
	 */
	read_0 = TlclRead(INDEX0, (uint8_t*) &index_0, sizeof(index_0));
	read_1 = TlclRead(INDEX1, (uint8_t*) &index_1, sizeof(index_1));
	read_2 = TlclRead(INDEX2, (uint8_t*) &index_2, sizeof(index_2));
	read_3 = TlclRead(INDEX3, (uint8_t*) &index_3, sizeof(index_3));
	if (read_0 != TPM_SUCCESS || read_1 != TPM_SUCCESS || read_2 !=
		TPM_SUCCESS || read_3 != TPM_SUCCESS) {
		enter_recovery_mode();
	}

	/* Writes space, and locks it.  Then attempts to write again.
	 * I really wish I could use the imperative.
	 */
	index_0 += 1;
	if (TlclWrite(INDEX0, (uint8_t*) &index_0, sizeof(index_0) !=
		TPM_SUCCESS)) {
		error("\tcould not write index 0\n");
	}
	TlclWriteLock(INDEX0);
	if (TlclWrite(INDEX0, (uint8_t*) &index_0, sizeof(index_0)) ==
		TPM_SUCCESS) {
		error("\tindex 0 is not locked\n");
	}

	printf("\tdone\n");
	return 0;
}

static int test_redefine_unowned(void)
{
	uint32_t perm;
	uint32_t result;
	uint32_t x;
	printf("Testing redefine_unowned ...");
	TlclLibInit();
	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclSelfTestFull());
	TPM_CHECK(TlclAssertPhysicalPresence());
	assert(!TlclIsOwned());

	/* Ensures spaces exist. */
	TPM_CHECK(TlclRead(INDEX0, (uint8_t*) &x, sizeof(x)));
	TPM_CHECK(TlclRead(INDEX1, (uint8_t*) &x, sizeof(x)));

	/* Redefines spaces a couple of times. */
	perm = TPM_NV_PER_PPWRITE | TPM_NV_PER_GLOBALLOCK;
	TPM_CHECK(TlclDefineSpace(INDEX0, perm, 2 * sizeof(uint32_t)));
	TPM_CHECK(TlclDefineSpace(INDEX0, perm, sizeof(uint32_t)));
	perm = TPM_NV_PER_PPWRITE;
	TPM_CHECK(TlclDefineSpace(INDEX1, perm, 2 * sizeof(uint32_t)));
	TPM_CHECK(TlclDefineSpace(INDEX1, perm, sizeof(uint32_t)));

	// Sets the global lock.
	TlclSetGlobalLock();

	// Verifies that index0 cannot be redefined.
	result = TlclDefineSpace(INDEX0, perm, sizeof(uint32_t));
	assert(result == TPM_E_AREA_LOCKED);

	// Checks that index1 can.
	TPM_CHECK(TlclDefineSpace(INDEX1, perm, 2 * sizeof(uint32_t)));
	TPM_CHECK(TlclDefineSpace(INDEX1, perm, sizeof(uint32_t)));

	// Turns off PP.
	TlclLockPhysicalPresence();

	// Verifies that neither index0 nor index1 can be redefined.
	result = TlclDefineSpace(INDEX0, perm, sizeof(uint32_t));
	assert(result == TPM_E_BAD_PRESENCE);
	result = TlclDefineSpace(INDEX1, perm, sizeof(uint32_t));
	assert(result == TPM_E_BAD_PRESENCE);

	printf("done\n");
	return 0;
}

#define PERMPPGL (TPM_NV_PER_PPWRITE | TPM_NV_PER_GLOBALLOCK)
#define PERMPP TPM_NV_PER_PPWRITE

static int test_space_perm(void)
{
	uint32_t perm;
	printf("Testing spaceperm ...");
	TlclLibInit();
	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclContinueSelfTest());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclGetPermissions(INDEX0, &perm));
	assert((perm & PERMPPGL) == PERMPPGL);
	TPM_CHECK(TlclGetPermissions(INDEX1, &perm));
	assert((perm & PERMPP) == PERMPP);
	printf("done\n");
	return 0;
}

static int test_startup(void)
{
	uint32_t result;
	printf("Testing startup ...\n");
	TlclLibInit();
	result = TlclStartup();
	if (result != 0) {
		printf("\ttpm startup failed with 0x%x\n", result);
	}
	result = TlclGetFlags(NULL, NULL, NULL);
	if (result != 0) {
		printf("\ttpm getflags failed with 0x%x\n", result);
	}
	printf("\texecuting SelfTestFull\n");
	TlclSelfTestFull();
	result = TlclGetFlags(NULL, NULL, NULL);
	if (result != 0) {
		printf("\ttpm getflags failed with 0x%x\n", result);
	}
	printf("\tdone\n");
	return 0;
}

/* Runs [op] and ensures it returns success and doesn't run longer than
 * [time_limit] in milliseconds.
 */
#define TTPM_CHECK(op, time_limit) do { \
	ulong start, time; \
	uint32_t __result; \
	start = get_timer(0); \
	__result = op; \
	if (__result != TPM_SUCCESS) { \
		printf("\t" #op ": error 0x%x\n", __result); \
		return (-1); \
	} \
	time = get_timer(start); \
	printf("\t" #op ": %lu ms\n", time); \
	if (time > (ulong)time_limit) { \
		printf("\t" #op " exceeded " #time_limit " ms\n"); \
	} \
} while (0)


static int test_timing(void)
{
	uint32_t x;
	uint8_t in[20], out[20];
	printf("Testing timing ...");
	TlclLibInit();
	TTPM_CHECK(TlclStartupIfNeeded(), 50);
	TTPM_CHECK(TlclContinueSelfTest(), 100);
	TTPM_CHECK(TlclSelfTestFull(), 1000);
	TTPM_CHECK(TlclAssertPhysicalPresence(), 100);
	TTPM_CHECK(TlclWrite(INDEX0, (uint8_t*) &x, sizeof(x)), 100);
	TTPM_CHECK(TlclRead(INDEX0, (uint8_t*) &x, sizeof(x)), 100);
	TTPM_CHECK(TlclExtend(0, in, out), 200);
	TTPM_CHECK(TlclSetGlobalLock(), 50);
	TTPM_CHECK(TlclLockPhysicalPresence(), 100);
	printf("done\n");
	return 0;
}

#define TPM_MAX_NV_WRITES_NOOWNER 64

static int test_write_limit(void)
{
	printf("Testing writelimit ...\n");
	int i;
	uint32_t result;
	TlclLibInit();

	TPM_CHECK(TlclStartupIfNeeded());
	TPM_CHECK(TlclSelfTestFull());
	TPM_CHECK(TlclAssertPhysicalPresence());
	TPM_CHECK(TlclForceClear());
	TPM_CHECK(TlclSetEnable());
	TPM_CHECK(TlclSetDeactivated(0));

	for (i = 0; i < TPM_MAX_NV_WRITES_NOOWNER + 2; i++) {
		printf("\twriting %d\n", i);
		if ((result = TlclWrite(INDEX0, (uint8_t*)&i, sizeof(i))) !=
			TPM_SUCCESS) {
			switch (result) {
			case TPM_E_MAXNVWRITES:
				assert(i >= TPM_MAX_NV_WRITES_NOOWNER);
			default:
				error("\tunexpected error code %d (0x%x)\n",
					result, result);
			}
		}
	}

	/* Reset write count */
	TPM_CHECK(TlclForceClear());
	TPM_CHECK(TlclSetEnable());
	TPM_CHECK(TlclSetDeactivated(0));

	/* Try writing again. */
	TPM_CHECK(TlclWrite(INDEX0, (uint8_t*)&i, sizeof(i)));
	printf("\tdone\n");
	return 0;
}

#ifdef CONFIG_TLCL_SEAL
/* added for Seal/Unseal tests */
static int test_test_seal(void)
{
	uint32_t result;
	uint32_t keyHandle;
	uint32_t pcrMap;
	uint8_t keyAuth[20];
	uint8_t dataAuth[20];

	uint8_t pcrInfo[256];

	uint8_t data[256 * 2];
	uint8_t blob[256 * 2];
	uint32_t blobSize, dataSize;

	/* TPM must have run TakeOwnership */
	keyHandle = 0x40000000; /*SRK*/
	pcrMap = 0 + (1<<1) + (1<<4);
	/* hashss of passwords, 0's for well-known */
	memset(keyAuth, 0, 20);
	memset(dataAuth, 0, 20);

	memset(data, 0x9, 256 * 2);
	memset(blob, 0, 256 * 2);

	printf("Testing seal ...\n");

	result = TlclSeal(keyHandle, pcrInfo, 0,
		keyAuth, dataAuth, data, 20, blob, &blobSize);
	printf("seal finished: %d (size=%d)\n", result, blobSize);
	printf("...done\n");

	memset(data, 0, 256 * 2);

	printf("Testing unseal (correct) ...\n");

	result = TlclUnseal(keyHandle, keyAuth, dataAuth,
		blob, blobSize, data, &dataSize);
	if (result == 0x15) {
		TlclReset();
		test_startup();
		result = TlclUnseal(keyHandle, keyAuth, dataAuth,
			blob, blobSize, data, &dataSize);
	}
	printf("unseal finished: %d (size=%d)\n", result, dataSize);

	return 0;
}

#endif

#ifdef CONFIG_TLCL_KEYS
static int test_createkey(void)
{
	uint8_t parentPass[20];
	uint8_t keyPass[20];
	uint8_t migrationPass[20];
	Tlcl_KeyData input, output;

	uint8_t blob[4096];
	uint32_t blobSize;
	uint32_t result;

	/* set well-known password for SRK */
	memset(parentPass, 0, 20);
	memset(keyPass, 0, 20);
	memset(migrationPass, 0, 20);

	memset(&input, 0, sizeof(Tlcl_KeyData));
	memset(&output, 0, sizeof(Tlcl_KeyData));

	sha1_csum("password1", 9, keyPass);

	input.keyflags = 0;
	input.authdatausage = 1; /* 0 = well-known, 1=password */

	input.privkeylen = 0; /* no privatekey */
	input.pub.algorithm = 0x00000001; /* RSA */
	input.keyusage = 0x0011; /* encryption */
	input.pub.encscheme = 0x0003; /* encryption scheme: RSA */
	input.pub.sigscheme = 0x0001; /* signature scheme: NONE */
	input.pub.keybitlen = 2048; /* RSA modulus: 2048 bits */
	input.pub.numprimes = 2; /* required */
	input.pub.expsize = 0; /* RSA exponent */
	input.pub.keylength = 0; /* no input key */
	input.pub.pcrinfolen = 0; /* no PCR's used */

	/* no migration password */
	result = TlclCreateWrapKey(0x40000000, parentPass, keyPass, NULL, &input, &output, blob, &blobSize);

	printf("...again\n");

	return 0;
}
#endif
/* end seal/unseal tests */

/* u-boot command table (include/command.h)
 */

#define VOIDTEST(XFUNC) \
	int do_test_##XFUNC(cmd_tbl_t *cmd_tbl, int flag, int argc, \
	char * const argv[]) \
	{ \
		return test_##XFUNC(); \
	} \

	/* above blank line is a part of the macro */

#define VOIDENT(XNAME) \
  U_BOOT_CMD_MKENT(XNAME, 0, 1, do_test_##XNAME, "", "")

VOIDTEST(early_extend)
VOIDTEST(early_nvram)
VOIDTEST(early_nvram2)
VOIDTEST(enable)
VOIDTEST(fast_enable)
VOIDTEST(global_lock)
VOIDTEST(lock)
VOIDTEST(readonly)
VOIDTEST(redefine_unowned)
VOIDTEST(space_perm)
VOIDTEST(startup)
VOIDTEST(timing)
VOIDTEST(write_limit)
#ifdef CONFIG_TLCL_SEAL
VOIDTEST(test_seal)
#endif
VOIDTEST(reset)
#ifdef CONFIG_TLCL_KEYS
VOIDTEST(createkey)
#endif
VOIDTEST(timer)

static cmd_tbl_t cmd_tpm_tlcl_sub[] = {
	VOIDENT(early_extend),
	VOIDENT(early_nvram),
	VOIDENT(early_nvram2),
	VOIDENT(enable),
	VOIDENT(fast_enable),
	VOIDENT(global_lock),
	VOIDENT(lock),
	VOIDENT(readonly),
	VOIDENT(redefine_unowned),
	VOIDENT(space_perm),
	VOIDENT(startup),
	VOIDENT(timing),
	VOIDENT(write_limit),
#ifdef CONFIG_TLCL_SEAL
	VOIDENT(test_seal),
#endif
	VOIDENT(reset),
#ifdef CONFIG_TLCL_KEYS
	VOIDENT(createkey),
#endif
	VOIDENT(timer),
};

/* u-boot shell commands
 */
static int do_tpm_tlcl(cmd_tbl_t * cmdtp, int flag, int argc,
	char * const argv[])
{
	cmd_tbl_t *c;
	printf("argc = %d, argv = ", argc);
	do {
		int i = 0;
		for (i = 0; i < argc; i++)
			printf(" %s", argv[i]);
			printf("\n------\n");
		} while(0);
	argc--;
	argv++;
	c = find_cmd_tbl(argv[0], cmd_tpm_tlcl_sub,
		ARRAY_SIZE(cmd_tpm_tlcl_sub));
	return c ? c->cmd(cmdtp, flag, argc, argv) : cmd_usage(cmdtp);
}

U_BOOT_CMD(tpm_tlcl, 2, 1, do_tpm_tlcl, "TPM_Lite tests",
	"\n\tearly_extend\n"
	"\tearly_nvram\n"
	"\tearly_nvram2\n"
	"\tenable\n"
	"\tfast_enable\n"
	"\tglobal_lock\n"
	"\tlock\n"
	"\treadonly\n"
	"\tredefine_unowned\n"
	"\tspace_perm\n"
	"\tstartup\n"
	"\ttiming\n"
	"\twrite_limit\n"
#ifdef CONFIG_TLCL_SEAL
	"\ttest_seal\n"
#endif
	"\treset\n"
#ifdef CONFIG_TLCL_KEYS
	"\tcreatekey\n"
#endif
);
