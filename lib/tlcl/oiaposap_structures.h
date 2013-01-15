/*
 * tlcl OIAP/OSAP structures
 * Copyright (C) 2012 V Lab Technologies
 * Author: Teddy Reed
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#ifndef OIAPOSAP_STRUCTURES_H_
#define OIAPOSAP_STRUCTURES_H_

const struct s_tpm_oiap_open_cmd {
	uint8_t buffer[10];
} tpm_oiap_open_cmd = {{
	0x0, 0xc1,
	0x0, 0x0, 0x0, 0xa,
	0x0, 0x0, 0x0, 0xa
}, };

const struct s_tpm_osap_open_cmd {
	uint8_t buffer[64];
	uint8_t type;
	uint8_t value;
	uint8_t nonce;
} tpm_osap_open_cmd = {{
	0x0, 0xc1,
	0x0, 0x0, 0x0, 0x24, /* 2 + 4 + 4 + 2 + 4 + 20 */
	0x0, 0x0, 0x0, 0x0B,
}, 10, 12, 16};

const struct s_tpm_handle_close_cmd {
	uint8_t buffer[14];
	uint16_t handle;
} tpm_handle_close_cmd = {{
	0x0, 0xc1,
	0x0, 0x0, 0x0, 0xe,
	0x0, 0x0, 0x0, 0x96,
}, 10, };


#endif /* OIAPOSAP_STRUCTURES_H_ */
