/*
 *  byteops.c: byte operations used by mincrypt system's asymmetric approach
 *
 *  Copyright (c) 2010-2012, Michal Novotny <mignov@gmail.com>
 *  All rights reserved.
 *
 *  See COPYING for the license of this software
 *
 */

#include "mincrypt.h"

#ifndef DISABLE_DEBUG
#define DEBUG_BYTEOPS
#endif

#ifdef DEBUG_BYTEOPS
#define DPRINTF(fmt, args...) \
do { fprintf(stderr, "[mincrypt/byteops     ] " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

uint64_t bits_to_num(char *bits, int num)
{
	int i;
	uint64_t ret = 0;
	int append_bits = 0;
	char *pbits = NULL;

	if (num > 64) {
		DPRINTF("%s: Num is too big (%d), trimming to 64\n", __FUNCTION__, num);
		num = 64;
	}

	if (strlen(bits) > num)
		bits[ num - 1] = 0;

	if (strlen(bits) < num) {
		append_bits = num - strlen(bits);
		DPRINTF("%s: append_bits is %d\n", __FUNCTION__, append_bits);
		if (append_bits > 0) {
			pbits = (char *)malloc( (num+2) * sizeof(char) );
			memset(pbits, 0, num + 2);
			DPRINTF("%s: Allocating %d bytes\n", __FUNCTION__, num);
			strcat(pbits, bits);
			for (i = 0; i < append_bits; i++)
				strcat(pbits, "0");
		}
	}
	else
		pbits = strdup(bits);

	DPRINTF("%s: pBits set to '%s' (%ld bits)\n", __FUNCTION__, pbits, (unsigned long)strlen(pbits));

	for (i = num; i > 0; i--) {
		if (pbits[i-1] == '1')
			ret += pow(2, (num - 1) - (i - 1));
	}
	free(pbits);

	DPRINTF("%s('%s', %d) returning 0x%" PRIx64 "\n", __FUNCTION__, bits, num, ret);
	return ret;
}

char *num_to_bits(uint64_t code, int *out_bits)
{
	int i = 0;
	int num_bits = 0;
	char *bits = NULL;
	uint64_t tmpcode = 0;

	while (tmpcode < code)
		tmpcode = pow(2, i++);

	num_bits = i - 1;
	DPRINTF("%s: %d bits\n", __FUNCTION__, num_bits);

	if (out_bits != NULL)
		*out_bits = num_bits;

	bits = (char *)malloc((num_bits + 2) * sizeof(char));
	if (bits == NULL) {
		DPRINTF("%s: Cannot allocate memory\n", __FUNCTION__);
		return NULL;
	}
	memset(bits, 0, num_bits + 1);
	for (i = num_bits - 1; i >= 0; i--)
		strcat(bits, (code & (uint64_t)pow(2, i)) ? "1" : "0");

	DPRINTF("%s(0x%" PRIx64 ", ...) returning '%s' (%d bits)\n", __FUNCTION__, code, bits, num_bits);
	return bits;
}

char *align_bits(char *bits, int num)
{
	uint64_t u64;
	char *obits = NULL;

	DPRINTF("%s: Aligning to %d bits\n", __FUNCTION__, num);

	u64 = bits_to_num( bits, num );
	obits = num_to_bits( u64, &num );

	if (num < 0)
		return bits;

	DPRINTF("%s: Aligned to %d bits\n", __FUNCTION__, num);

	return obits;
}

int get_number_of_bits_set(char *bits, int flags)
{
	int i, num = 0;

	for (i = 0; i < strlen(bits); i++) {
		if (((bits[i] == '0') && (flags & BIT_UNSET))
			|| ((bits[i] == '1') && flags & BIT_SET))
			num++;
	}

	return num;
}

int apply_binary_operation_on_byte(int tbit, int kbit, int operation)
{
	if (operation == BINARY_OPERATION_OR) {
		return ((tbit == '1') || (kbit == '1')) ? '1' : '0';
	}
	else
	if (operation == BINARY_OPERATION_AND) {
		return ((tbit == '1') && (kbit == '1')) ? '1' : '0';
	}
	else
	if (operation == BINARY_OPERATION_XOR) {
		return (((tbit == '0') && (kbit == '1'))
				|| ((tbit == '1') && (kbit == '0'))) ? '1' : '0';
	}

	return '?';
}

char *apply_binary_operation(char *tbits, char *kbits, int operation)
{
	int i;
	char *out = NULL;

	if (strlen(tbits) != strlen(kbits)) {
		DPRINTF("%s: Fatal error! Text bits != key bits!\n", __FUNCTION__);
		return NULL;
	}

	DPRINTF("%s: Applying %s operation on text and key pattern\n",
		__FUNCTION__, (operation == BINARY_OPERATION_OR) ? "OR" :
			((operation == BINARY_OPERATION_AND) ? "AND" :
			((operation == BINARY_OPERATION_XOR) ? "XOR" : "UNKNOWN")));

	out = (char *)malloc( (strlen(tbits)+1) * sizeof(char));
	memset(out, 0, strlen(tbits)+1);

	for (i = 0; i < strlen(tbits); i++)
		out[i] = apply_binary_operation_on_byte(tbits[i], kbits[i], operation);

	return out;
}

char *dec_to_hex(int dec)
{
	char buf[256] = { 0 };

	snprintf(buf, sizeof(buf), "%02x", dec);
	return strdup(buf);
}

uint64_t pow_and_mod(uint64_t n, uint64_t e, uint64_t mod)
{
	uint64_t i;
	uint64_t val = n;

	for (i = 1; i < e; i++) {
		val *= n;

		if (val > mod)
			val %= mod;
	}

	return val;
}

int find_element_index(const char *str, int c)
{
	int i;

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == c)
			return i;
	}

	return -1;
}

void four_numbering_system_set_quartet(char *quartet)
{
	int i, j;

	if (strlen(quartet) != 4)
		return;

	/* Ensure there's no duplicity in the quartet characters */
	/* Otherwise decoding would fail on duplicate characters */
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			if ((quartet[i] == quartet[j])
				&& (i != j))
				return;

	strncpy(gQuartet, quartet, 4);
}

char *four_numbering_system_get_quartet(void)
{
	return strdup(gQuartet);
}

unsigned char *four_numbering_system_encode(unsigned char *data, int len)
{
	int i, val;
	char a[5] = { 0 };
	unsigned char *output = NULL;

	output = (unsigned char *)malloc( (len * 4) * sizeof(unsigned char) );
	memset(output, 0, (len * 4) * sizeof(unsigned char));
	for (i = 0; i < len; i++) {
		val = data[i];

		memset(a, 0, 5);
		a[0] = gQuartet[(val / 64) % 4];
		a[1] = gQuartet[(val / 16) % 4];
		a[2] = gQuartet[(val / 4 ) % 4];
		a[3] = gQuartet[(val / 1 ) % 4];

		strcat((char *)output, a);
	}

	return output;
}

unsigned char *four_numbering_system_decode(unsigned char *data, int len)
{
	int i, j, k, val;
	unsigned char *output = NULL;

	if (len % 4 != 0)
		return NULL;

	output = (unsigned char *)malloc( (len / 4) * sizeof(unsigned char) );
	memset(output, 0, (len / 4) * sizeof(unsigned char) );

	for (i = 0; i < len; i += 4) {
		val = 0;
		for (j = 0; j < strlen(gQuartet); j++) {
			k = find_element_index(gQuartet, data[i+j]);
			if (k < 0) {
				free(output);
				return NULL;
			}
			val += (k * pow(4, 4 - (j + 1)));
		}

		output[i / 4] = val;
	}

	return output;
}

int four_numbering_system_test(unsigned char *data, int len)
{
	int ret;
	unsigned char *tmp1 = NULL;
	unsigned char *tmp2 = NULL;

	if ((tmp1 = four_numbering_system_encode(data, len)) == NULL)
		return -EIO;

	if ((tmp2 = four_numbering_system_decode(tmp1, len * 4)) == NULL) {
		free(tmp1);
		return -EINVAL;
	}

	ret = (strcmp((char *)data, (char *)tmp2) != 0);
	free(tmp1);
	free(tmp2);

	return ret;
}

