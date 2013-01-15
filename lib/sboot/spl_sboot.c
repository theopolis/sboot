/*
 * spl_sboot.c
 */

#include <common.h>
#include <image.h>
#include <spl.h>
#include <sha1.h>
#include <i2c.h>

#include <sboot.h>

/* spl_image defined in spl.c */
void spl_sboot_extend(void)
{
	uint8_t csum[20];
	uint8_t out_digest[20];

	uint8_t image_buffer[SBOOT_SPL_READ_SIZE];
	uint32_t i;
	SHA1_CTX ctx;

	sha1_starts(&ctx);
	/* Only support MMC/FAT */
#if defined(CONFIG_SPL_MMC_SUPPORT) && defined(CONFIG_SPL_FAT_SUPPORT)
	/* Todo: add a configuration option to limit the memory read length.
	 * This will allow us to SHA1 in blocks.
	 * Todo: add a configuration option to use the TPM's SHA1 for extreme
	 * memory contention scenarios. */
	sha1_update(&ctx, (unsigned char *) spl_image.load_addr, spl_image.size);
#else
#warning "Warning: sboot does not support the U-Boot storage configuration."
#endif
	sha1_finish(&ctx, csum);

	if (sboot_extend(SBOOT_PCR_UBOOT, csum, out_digest) != SBOOT_SUCCESS) {
		puts("SPL: (sboot) error while measuring U-Boot\n");
		return;
	}

	sha1_starts(&ctx);
	/* Extend EEPROM, support I2C only */
#ifdef CONFIG_ENV_EEPROM_IS_ON_I2C
	/*
	for (i = 0; i * SBOOT_SPL_READ_SIZE < CONFIG_SYS_I2C_EEPROM_SIZE; ++i) {
		memset(image_buffer, 0, SBOOT_SPL_READ_SIZE);
		if (i2c_read(CONFIG_SYS_I2C_EEPROM_ADDR, 0, CONFIG_SYS_I2C_EEPROM_ADDR_LEN,
				image_buffer, SBOOT_SPL_READ_SIZE)) {
			puts("SPL: (sboot) could not read the EEPROM\n");
			return;
		}
		sha1_update(&ctx, image_buffer, SBOOT_SPL_READ_SIZE);
	}*/
	debug("SPL: (sboot) measuring EEPROM\n");
	i2c_read(CONFIG_SYS_I2C_EEPROM_ADDR, 0, CONFIG_SYS_I2C_EEPROM_ADDR_LEN, image_buffer, CONFIG_SYS_I2C_EEPROM_SIZE);
	sha1_update(&ctx, image_buffer, CONFIG_SYS_I2C_EEPROM_SIZE);
	debug("SPL: (sboot) finished\n");
#else
#warning "Warning: sboot does not support the ENV storage configuration."
#endif
	sha1_finish(&ctx, csum);

	if (sboot_extend(SBOOT_PCR_CHIPSET_CONFIG, csum, out_digest) != SBOOT_SUCCESS) {
		puts("SPL: (sboot) error while measuring chipset config\n");
		return;
	}
}

void spl_sboot_check(void)
{
#ifndef CONFIG_SBOOT_UBOOT_SEAL_INDEX
	puts("SPL: (sboot) no U-boot seal index defined\n");
	hang();
#endif

	puts("SPL: (Sboot) measuring U-Boot ... ");
	if (sboot_check(SBOOT_NV_INDEX_SEAL_UBOOT) != SBOOT_SUCCESS) {
		/* If CONFIG_SBOOT_ENFORCE is enabled the system is already hung. */
		puts("Failed\n");
		return;
	}

	puts("OK\n");
}
