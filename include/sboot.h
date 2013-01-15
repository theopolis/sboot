/* Secure Boot implemented with a Static Root of Trust Measurement (SRTM).
 * The Static Root is assuming to be implemented in SPL (Second Phase Loader),
 * thus we can implement a trusted or secure boot with relying on chip or board
 * manufactures. The implementor must ensure the SPL executes from Read-Only NV storage.
 *
 * BeagleBone implementation of SRTM using SPL:
 * 	 Public ROM (operating in public-CPU mode) boots from a hard-order: mmc0, spi0, uart0, usb0.
 * 	 By loading SPL on MMC0, and pulling the WP pin on MMC0 high we prevent modification to the SPL.
 * 	 (This can also be implemented using spi0, or uart0, without attaching an MMC0.)
 * 	 U-Boot, boot configuration data (i.e., uEnv.txt), kernel, and disk are located on MMC1.
 *
 * TPM Operations (Baseline Trusted Boot Components):
 *   SPL: sboot_init() -> initialize TPM, run SelfTest, enable physical presence
 *   SPL: sboot_read_uboot() -> PCR Extend for "firmware"
 *   SPL: sboot_read_eeprom() -> PCR Extend for EEPROM data
 *   UBT: sboot_read_bootoptions() -> PCR Extend for boot configuration data, may include additional EEPROM data
 *   UBT: sboot_read_kernel() -> PCR Extend for Linux kernel
 *   UBT: sboot_seal() -> Save PCR context using Skey^i to untrusted store
 *   	- verify key can be used for secure storage
 *   	- create context using key and PCR values (uboot, config, kernel)
 *   	- generate symmetric encryption key (FSkey) for filesystem
 *   	- encrypt, store, and return FSkey
 *   	- optionally encrypt FS on MMC1
 *
 * TPM Operations (Booting Securely):
 *   SPL: sboot_init() -> initialize TPM, run SelfTest, enable physical presence
 *   SPL: sboot_read_uboot() -> PCR Extend for boot loader
 *   	- read u-boot binary from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_UBOOT
 *   SPL: sboot_read_eeprom() -> PCR Extend for EEPROM data
 *   	- read EEPROM (various methods)
 *   	- calculate SHA1, extend SBOOT_PCR_UBOOT
 *   UBT: sboot_read_bootoptions() -> PCR Extend for boot configuration data
 *   	- read uEnv.txt from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_UBOOT
 *   UBT: sboot_read_kernel() -> PCR Extend for Linux kernel
 *   	- read uImage from mmc1
 *   	- calculate SHA1, extend SBOOT_PCR_KERNEL
 *   KRN: sboot_unseal() -> [or UBT] Decrypt filesystem symmetric encryption key.
 *   	- use SKey^i and PCRs to unseal protected storage
 *   KRN: sboot_lock_pcrs() -> extend all used PCRs with random data
 *   KRN: sboot_finish() -> optionally remove physical presence
 *
 */
#ifndef SBOOT_H_
#define SBOOT_H_

#include <common.h>
#include <tpm.h>

#include <tlcl.h>

/* TSS-defined (section here) PCR locations for UBOOT and OS Kernel */
/* Todo: this should be represented as a linked list, this will ease iteration
 * and allow developers to easily add data for measurement (other than static
 * defines of PCR values).
 */
#define SBOOT_PCR_UBOOT 0x1
#define SBOOT_PCR_CHIPSET_CONFIG 0x2
#define SBOOT_PCR_UBOOT_ENVIRONMENT 0x3
#define SBOOT_PCR_UBOOT_CONSOLE 0x4
#define SBOOT_PCR_UBOOT_MEMORY 0x4
#define SBOOT_PCR_KERNEL 0x5

#define SBOOT_SPL_READ_SIZE (0x1 << 15) /* 32K */

/* Temporary (simple) SBOOT errors */
#define SBOOT_SUCCESS 0x0
#define SBOOT_TPM_ERROR 0x1
#define SBOOT_DATA_ERROR 0x2

#define SBOOT_SEAL_WELL_KNOWN_KEY 		0x10
#define SBOOT_NV_INDEX_SEAL_OS			0xd000
#define SBOOT_NV_INDEX_SEAL_UBOOT		0xe000

/* SPL functions */
/* Extend PCRs for U-boot and EEPROM */
void spl_sboot_extend(void);
/* Load sealed data and verify */
void spl_sboot_check(void);

/* U-Boot functions */
__attribute__((unused))
uint8_t sboot_extend_console(const char *buffer, uint32_t size);
__attribute__((unused))
uint8_t sboot_extend_environment(const char *buffer, uint32_t size);

/* Seal toggle will set an environment variable that bootm checks.
 * If this variable is still set when bootm is executed, it will
 * run sboot_seal_os(void); which is a simple wrapper for sboot_seal
 * with a well-known key value and configured nv_index as SBOOT_NV_INDEX_SEAL_OS.
 */
__attribute__((unused))
uint8_t sboot_seal_toggle(void);
__attribute__((unused))
uint8_t sboot_seal_os(void);
__attribute__((unused))
uint8_t sboot_seal_uboot(void);
uint8_t sboot_seal(const uint8_t *key, uint32_t keySize,
	uint32_t pcrMap, uint16_t nv_index);
uint8_t sboot_unseal(const uint8_t *sealData, uint32_t sealDataSize,
	uint8_t *unsealData, uint32_t *unsealDataSize);

/* Initialization steps needed for TPM:
 * 	TlclStartup()
 * 	TlclSelfTestFull() //optional
 */
__attribute__((unused))
uint8_t sboot_init(void);

__attribute__((unused))
uint8_t sboot_check_os(void);
uint8_t sboot_check(uint16_t nv_index);

/* Performs a TlclExtend (TPM PCR Extend) with the given 20 byte hash */
uint8_t sboot_extend(uint16_t pcr, const uint8_t* in_digest, uint8_t* out_digest);

uint8_t sboot_read_uboot(const uint8_t* in_digest);
uint8_t sboot_read_kernel(const uint8_t* in_digest);
uint8_t sboot_read_bootoptions(const uint8_t* in_digest);

/* After system is booted, lock PCRS by extending with random data. */
__attribute__((unused))
uint8_t sboot_lock_pcrs(void);
__attribute__((unused))
uint8_t sboot_finish(void);

#endif /* SBOOT_H_ */
