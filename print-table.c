/*
 * Copyright (c) 2020, Jason Wu <oblitorum@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the Jason Wu.
 * 4. Neither the name of the Jason Wu nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY Jason Wu ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Jason Wu BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "netdissect-stdinc.h"

#include <stdio.h>

#include "netdissect.h"
#include "extract.h"

#include <fort.h>

#define DISPLAY_BINARY 1
#define DISPLAY_DECIMAL 2
#define DISPLAY_HEX 3
#define DISPLAY_IPv4 4
#define DISPLAY_ASCII 5

struct proto_field {
	char *name;			// name of field
	uint length;		// bits length of field
	uint offset;        // bits offset
	int display_type;	// display type of filed
};

// split the fileds manually for better display effect
// TODO:
// - consider split the fileds dynamically
// - variable filed support. eg. Option
static struct proto_field ip[][4] = {
	{
		{ "Version", 4, 0, DISPLAY_DECIMAL },
		{ "IHL", 4, 4, DISPLAY_DECIMAL },
		{ "Type of Service", 8, 8, DISPLAY_BINARY },
		{ "Total Length", 16, 16, DISPLAY_DECIMAL }
	},
	{
		{ "Identification", 16, 32, DISPLAY_DECIMAL },
		{ "Flags", 3, 48, DISPLAY_BINARY },
		{ "Flagment Offset", 13, 51, DISPLAY_DECIMAL },
		{ "Time To Live", 8, 64, DISPLAY_DECIMAL }
	},
	{
		{ "Protocol", 8, 72, DISPLAY_DECIMAL },
		{ "Header Checksum", 16, 80, DISPLAY_HEX },
		{ "Source Address", 32, 96, DISPLAY_IPv4 },
		{ "Destination Address", 32, 128, DISPLAY_IPv4 }
	}
};

// convert bits to u_int64_t number
u_int64_t
bits_to_number(const u_char *bytes, uint length, u_int offset)
{
	u_int offset_in_byte = offset % 8, bits = length + offset_in_byte;
	const u_char *ptr = bytes + offset / 8;
	if (bits > 64) { // over 64-bit number is not supported
		return 0;
	}

	u_int64_t number, extra_bits;
	if (bits <= 8) {
		number = (u_int8_t)(*ptr << offset_in_byte) >> (8 - length);
	} else if (bits <= 16) {
		number = (u_int16_t)(EXTRACT_BE_U_2(ptr) << offset_in_byte) >> (16 - length);
	} else if (bits <= 32) {
		number = (u_int32_t)(EXTRACT_BE_U_4(ptr) << offset_in_byte) >> (32 - length);
	} else {
		number = (u_int64_t)(EXTRACT_BE_U_8(ptr) << offset_in_byte) >> (64 - length);
	}

	return number;
}

// convert bits to different display type. eg. binary, decimal, ip.
// notice that the 'char *' returned is dynamically allocated, should
// be free when not needed anymore.
char *
bits_to_display(const u_char *bytes, int type, uint length, u_int offset)
{
	char *buff = NULL, byte;
	int op, byte_length;
	uint ip_parts[4];
	u_int64_t number, ip;

	switch (type) {
	case DISPLAY_BINARY:
		buff = (char *)malloc(length+3), buff[0] = '0', buff[1] = 'b';
		number = bits_to_number(bytes, length, offset);
		for (int counter = 0; counter < length; counter++) {
			buff[counter+2] = 48 + (1 & (number >> (length - counter - 1)));
		}
		buff[length+2] = '\0';

		break;
	case DISPLAY_DECIMAL:
		number = bits_to_number(bytes, length, offset);
		buff = (char *)malloc(21); // maximum 64-bit number
		sprintf(buff, "%llu", number);

		break;
	case DISPLAY_HEX:
		number = bits_to_number(bytes, length, offset);
		buff = (char *)malloc(21); // maximum 64-bit number
		sprintf(buff, "0x%llx", number);
		
		break;
	case DISPLAY_IPv4:
		if (length != 32) // invalid ipv4
			break;

		ip = bits_to_number(bytes, length, offset);
		for (int i = 0; i < 4; i++) {
			u_int64_t op = 255ULL << (i * 8);
			ip_parts[i] = (uint)((op & ip) >> (i*8));
		}

		buff = (char *)malloc(16); // max length ip address
		sprintf(buff, "%d.%d.%d.%d", ip_parts[3], ip_parts[2], ip_parts[1], ip_parts[0]);
		
		break;
	case DISPLAY_ASCII:
		if (offset % 8 != 0 || length % 8 != 0)
			break;

		byte_length = length/8;
		buff = (char *)malloc(byte_length+1);
		memcpy((void *)buff, bytes + offset / 8, byte_length);
		buff[byte_length] = '\0';

		break;
	default:
		break;
	}

	return buff;
}

// TODO
// - support other protocols
void
table_print(netdissect_options *ndo,
			const u_char *cp, u_int length)
{
	u_int caplength;
	u_char s;

	caplength = (ndo->ndo_snapend > cp) ? ND_BYTES_AVAILABLE_AFTER(cp) : 0;
	if (length > caplength)
		length = caplength;

	ft_table_t *table = ft_create_table();
	ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
	
	ND_PRINT("\n");

	int rows = sizeof(ip) / sizeof(ip[0]);
	for (int i = 0; i < rows; i++) {
		int cols = sizeof(ip[i]) / sizeof(ip[i][0]);
		char *header[cols], *values[cols];

		for (int j = 0; j < cols && (ip[i][j].length + ip[i][j].offset)/8 <= caplength; j++) {
			header[j] = ip[i][j].name;
			values[j] = bits_to_display(cp, ip[i][j].display_type, ip[i][j].length, ip[i][j].offset);
		}

		ft_add_separator(table);
		ft_row_write_ln(table, cols, (const char **)header);
		ft_add_separator(table);
		ft_row_write_ln(table, cols, (const char **)values);

		// free dynamically allocated memory
		for (int j = 0; j < cols; j++) {
			if (values[j] != NULL) {
				free(values[j]);
			}
		}
	}

	printf("%s\n", ft_to_string(table));
	ft_destroy_table(table);
}
