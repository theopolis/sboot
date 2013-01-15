/*
 * cmd_sboot.c
 */

#include <common.h>
#include <command.h>
#include <environment.h>
#include <sboot.h>

#include <sha1.h>

static int test_seal(void)
{
	uint8_t result;

	/* First we seal the currently running U-Boot */
	printf("sboot: Sealing U-Boot\n");
	result = sboot_seal_uboot();
	if (result != SBOOT_SUCCESS) {
		printf("sboot: Failed to seal U-Boot\n");
		return 0;
	}

	/* Then we tell bootm to seal the os, initrd, external environment, and dtb.
	 * The user (and U-Boot) may continue to execute console commands and edit the
	 * environment. All changes will be measured and sealed when bootm runs.
	 *
	 * To abort the seal, reset the device or unset the environment variable 'sbootseal'.
	 */
	puts("sboot: When bootm next runs, it will seal the boot state\n");
	sboot_seal_toggle();

	return 0;
}

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

VOIDTEST(seal)


static cmd_tbl_t cmd_sboot_sub[] = {
	VOIDENT(seal),
};

/* u-boot shell commands
 */
static int do_sboot(cmd_tbl_t * cmdtp, int flag, int argc,
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
	c = find_cmd_tbl(argv[0], cmd_sboot_sub,
		ARRAY_SIZE(cmd_sboot_sub));
	return c ? c->cmd(cmdtp, flag, argc, argv) : cmd_usage(cmdtp);
}

U_BOOT_CMD(sboot, 2, 1, do_sboot, "sboot commands",
	"\n\tseal\n"
);
