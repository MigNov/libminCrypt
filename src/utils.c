/*
 * utils.c: Utilities used in mincrypt encryption system
 *
 * Copyright (c) 2010-2013, Michal Novotny <mignov@gmail.com>
 * All rights reserved.
 * See COPYING for the license of this software
 *
 */

#include "mincrypt.h"

#ifndef DISABLE_DEBUG
#define DEBUG_UTILS
#define DEBUG_UINT64_CONV
#endif

#ifdef DEBUG_UTILS
#define DPRINTF(fmt, args...) \
do { fprintf(stderr, "[mincrypt/utils       ] " fmt , ##args); } while (0)
#else
#define DPRINTF(fmt, args...) do {} while(0)
#endif

void mincrypt_init(void)
{
	akd_mincrypt_init();
}

unsigned long get_file_size(char *fn)
{
	struct stat st;

	if (fn == NULL)
		return 0;

	if (stat(fn, &st) != 0)
		return 0;

	return st.st_size;
}

unsigned char *uint64_to_binary(uint64_t n, int strip)
{
	int i;
	unsigned char *ret = NULL;

	ret = (unsigned char *)malloc( ((64-strip) + 1) * sizeof(unsigned char) );
	memset(ret, 0, ((64-strip) + 1) * sizeof(unsigned char) );
	for (i = 0; i < 64 - strip; i++)
		ret[(63 - strip) - i] = ((n >> i) & 1) ? '1' : '0';

	#ifdef DEBUG_UINT64_CONV
	DPRINTF("%s(%"PRIi64") returning %s\n", __FUNCTION__, n, ret);
	#endif
	return ret;
}

unsigned char *uint64_to_bytes(uint64_t n, int len)
{
	unsigned char *ret = NULL;
	unsigned char *tmp = (unsigned char *)malloc( 8 * sizeof(unsigned char) );

	tmp[0] = (int)((n >> 56) & 0xff);
	tmp[1] = (int)((n >> 48) & 0xff);
	tmp[2] = (int)((n >> 40) & 0xff);
	tmp[3] = (int)((n >> 32) & 0xff);
	tmp[4] = (int)((n >> 24) & 0xff);
	tmp[5] = (int)((n >> 16) & 0xff);
	tmp[6] = (int)((n >>  8) & 0xff);
	tmp[7] = (int)((n >>  0) & 0xff);

	if (len != 8) {
		ret = (unsigned char *)malloc( len * sizeof(unsigned char) );
		memset(ret, 0, sizeof(unsigned char));

		int j, k = 0;
		for (j = 8 - len; j < 8; j++)
			ret[k++] = tmp[j];
	}
	else
		ret = strdup(tmp);

#ifdef DEBUG_UINT64_CONV
	int i;
	DPRINTF("ret(%"PRIi64", %d) = {", n, len);

	for (i = 0; i < len; i++) {
		fprintf(stderr, " %d", ret[i]);
		if (i < len - 1)
			fprintf(stderr, ",");
	}
	fprintf(stderr, " }\n");
#endif

	return ret;
}

tRndValues generate_random_values(int num, uint64_t max)
{
	int i;
	tRndValues ret;

	ret.num = num;
	ret.vals = (uint64_t *)malloc( num * sizeof(uint64_t) );

	if (max == 0)
		max = 1 << 24;

	for (i = 0; i < num; i++)
		ret.vals[i] = rand() % max;

	return ret;
}

tAKDParams akd_parse_value(char *val)
{
	tTokenizer t;
	int count, step, type;
	char *filename = NULL;
	tAKDParams ret = AKD_PARAMS_EMPTY;

	t = tokenize_by(val, ":");
	if (t.numTokens < 2)
		goto cleanup;

	count = 0;
	if (strlen(t.tokens[0]) == 0)
		return ret;

	type = -1;
	if ((t.tokens[0][0] == 'r') || (t.tokens[0][0] == 'R'))
		type = MINCRYPT_FLAG_DHVAL_RECEIVER;
	else
	if ((t.tokens[0][0] == 's') || (t.tokens[0][0] == 'S'))
		type = MINCRYPT_FLAG_DHVAL_SENDER;

	if (type == -1)
		return ret;

	filename = strdup(t.tokens[2]);
	step = atoi(t.tokens[1]);
	if (step == 1) {
		if (t.numTokens < 4)
			goto cleanup;

		count = atoi(t.tokens[3]);
	}

	ret.type = type;
	ret.step = step;
	ret.filename = filename;
	ret.count = count;
cleanup:
	free_tokens(t);
	return ret;
}

int akd_write_shared(int fd, tAKDKeyPair kp, int flags)
{
	int i;
	char tmp[64] = { 0 };

	if (!(flags & MINCRYPT_FLAG_DHKEY_COMMON_P)
		&& (!(flags & MINCRYPT_FLAG_DHKEY_COMMON_G)))
		return -EINVAL;

	if (kp.common == NULL)
		return -EINVAL;

	/* Key value */
	if (flags & MINCRYPT_FLAG_DHKEY_COMMON_P) {
		snprintf(tmp, sizeof(tmp), "--- KEY VALUE FOR MINCRYPT ENCRYPTION ---\n");
		write(fd, tmp, strlen(tmp));
		for (i = 0; i < kp.num; i++) {
			memset(tmp, 0, sizeof(tmp));

			snprintf(tmp, sizeof(tmp), "%08"PRIx64, kp.common[i].p);
			write(fd, tmp, strlen(tmp));

			if ((i + 1) % 10 == 0)
				write(fd, "\n", 1);
		}

		if ((i + 1) % 10 != 1)
			write(fd, "\n", 1);

		snprintf(tmp, sizeof(tmp), "--- END OF KEY VALUE FOR MINCRYPT ENCRYPTION ---\n");
		write(fd, tmp, strlen(tmp));
	}

	/* Group value */
	if (flags & MINCRYPT_FLAG_DHKEY_COMMON_G) {
		snprintf(tmp, sizeof(tmp), "--- GROUP VALUE FOR MINCRYPT ENCRYPTION ---\n");
		write(fd, tmp, strlen(tmp));
		for (i = 0; i < kp.num; i++) {
			memset(tmp, 0, sizeof(tmp));

			snprintf(tmp, sizeof(tmp), "%08"PRIx64, kp.common[i].g);
			write(fd, tmp, strlen(tmp));

			if ((i + 1) % 10 == 0)
				write(fd, "\n", 1);
		}

		if ((i + 1) % 10 != 1)
			write(fd, "\n", 1);

		snprintf(tmp, sizeof(tmp), "--- END OF GROUP VALUE FOR MINCRYPT ENCRYPTION ---");
		write(fd, tmp, strlen(tmp));
	}

	return 0;
}

int akd_write_private(int fd, tAKDKeyPair kp)
{
	int i;
	char tmp[64] = { 0 };

	if (kp.vPrivate == NULL)
		return -EINVAL;

	/* Private value */
	snprintf(tmp, sizeof(tmp), "--- PRIVATE VALUE FOR MINCRYPT ENCRYPTION ---\n");
	write(fd, tmp, strlen(tmp));
	for (i = 0; i < kp.num; i++) {
		memset(tmp, 0, sizeof(tmp));

		snprintf(tmp, sizeof(tmp), "%08"PRIx64, kp.vPrivate[i]);
		write(fd, tmp, strlen(tmp));

		if ((i + 1) % 10 == 0)
			write(fd, "\n", 1);
	}

	if ((i + 1) % 10 != 1)
		write(fd, "\n", 1);

	snprintf(tmp, sizeof(tmp), "--- END OF PRIVATE VALUE FOR MINCRYPT ENCRYPTION ---");
	write(fd, tmp, strlen(tmp));

	return 0;
}

int akd_write_public(int fd, tAKDKeyPair kp)
{
	int i;
	char tmp[64] = { 0 };

	if (kp.vPublic == NULL)
		return -EINVAL;

	/* Public value */
	snprintf(tmp, sizeof(tmp), "--- PUBLIC VALUE FOR MINCRYPT ENCRYPTION ---\n");
	write(fd, tmp, strlen(tmp));
	for (i = 0; i < kp.num; i++) {
		memset(tmp, 0, sizeof(tmp));

		snprintf(tmp, sizeof(tmp), "%08"PRIx64, kp.vPublic[i]);
		write(fd, tmp, strlen(tmp));

		if ((i + 1) % 10 == 0)
			write(fd, "\n", 1);
	}

	if ((i + 1) % 10 != 1)
		write(fd, "\n", 1);

	snprintf(tmp, sizeof(tmp), "--- END OF PUBLIC VALUE FOR MINCRYPT ENCRYPTION ---");
	write(fd, tmp, strlen(tmp));

	return 0;
}

int akd_write_file(char *filename, tAKDKeyPair kp, int flags)
{
	int fd, ret;

	if ((!(flags & MINCRYPT_FLAG_DHKEY_COMMON_P))
		&& (!(flags & MINCRYPT_FLAG_DHKEY_PRIVATE))
		&& (!(flags & MINCRYPT_FLAG_DHKEY_PUBLIC))) {
		DPRINTF("%s: Invalid flags (%d) to open %s\n", __FUNCTION__, flags, filename);
		return -EINVAL;
	}

	fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		DPRINTF("%s: Cannot open file %s\n", __FUNCTION__, filename);
		return -EPERM;
	}

	if (flags & MINCRYPT_FLAG_DHKEY_COMMON_P) {
		ret = akd_write_shared(fd, kp, flags);
		if (ret != 0) {
			DPRINTF("%s: Write shared failed with error %d\n", __FUNCTION__, ret);
			close(fd);
			unlink(filename);
			return ret;
		}
	}

	if (flags & MINCRYPT_FLAG_DHKEY_PUBLIC) {
		if (flags & MINCRYPT_FLAG_DHKEY_COMMON_P)
			write(fd, "\n", 1);

		ret = akd_write_public(fd, kp);
		if (ret != 0) {
			DPRINTF("%s: Write public failed with error %d\n", __FUNCTION__, ret);
			close(fd);
			unlink(filename);
			return ret;
		}
	}

	if (flags & MINCRYPT_FLAG_DHKEY_PRIVATE) {
		if (flags & MINCRYPT_FLAG_DHKEY_COMMON_P)
			write(fd, "\n", 1);

		ret = akd_write_private(fd, kp);
		if (ret != 0) {
			DPRINTF("%s: Write private failed with error %d\n", __FUNCTION__, ret);
			close(fd);
			unlink(filename);
			return ret;
		}
	}

	close(fd);
	return 0;
}

tTokenizerU64 split_line_by_number_of_chars(char *input, int num)
{
	int idx, c;
	char *tmp = NULL;
	char *tmpX = NULL;
	char tmpC[2] = { 0 };
	tTokenizerU64 ret;

	tmp = (char *)malloc( (num + 1) * sizeof(char) );
	memset(tmp, 0, (num + 1) * sizeof(char));

	idx = 0;
	ret.numVals = 0;
	ret.vals = (uint64_t *)malloc( sizeof(uint64_t) );
	while ((c = *input++) != NULL) {
		tmpC[0] = c;
		strcat(tmp, tmpC);

		idx++;
		if (num == idx) {
			ret.vals = (uint64_t *) realloc( ret.vals, (ret.numVals + 1) * sizeof(uint64_t) );

			ret.vals[ret.numVals] = strtoull(tmp, &tmpX, 16);
			ret.numVals++;

			memset(tmp, 0, (num + 1) * sizeof(char));
			idx = 0;
		}
	}

	return ret;
}

void akd_mincrypt_init(void)
{
	AKD_KEYPAIR_EMPTY.num = 0;
	AKD_KEYPAIR_EMPTY.common = NULL;
	AKD_KEYPAIR_EMPTY.vPrivate = NULL;
	AKD_KEYPAIR_EMPTY.vPublic = NULL;

	AKD_PARAMS_EMPTY.type = -1;
	AKD_PARAMS_EMPTY.step = 0;
	AKD_PARAMS_EMPTY.count = 0;
	AKD_PARAMS_EMPTY.filename = NULL;

	AKD_DATA_EMPTY.afilename_common = NULL;
	AKD_DATA_EMPTY.afilename_private = NULL;
	AKD_DATA_EMPTY.afilename_public = NULL;
	AKD_DATA_EMPTY.bfilename_common = NULL;
	AKD_DATA_EMPTY.bfilename_private = NULL;
	AKD_DATA_EMPTY.bfilename_public = NULL;
	AKD_DATA_EMPTY.afilename_common_size = 0;
	AKD_DATA_EMPTY.afilename_private_size = 0;
	AKD_DATA_EMPTY.afilename_public_size = 0;
	AKD_DATA_EMPTY.bfilename_common_size = 0;
	AKD_DATA_EMPTY.bfilename_private_size = 0;
	AKD_DATA_EMPTY.bfilename_public_size = 0;
	AKD_DATA_EMPTY.step = -1;
	AKD_DATA_EMPTY.direction = -1;
	AKD_DATA_EMPTY.num = 0;
	AKD_DATA_EMPTY.vals = NULL;
}

int akd_get_number_of_elements(char *filename)
{
	FILE *fp = NULL;
	char buf[100] = { 0 };
	int ret = 0;
	tTokenizerU64 vals;

	if (access(filename, R_OK) != 0)
		return 0;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return 0;
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, 100, fp);

		if (strlen(buf) > 0)
			buf[strlen(buf) - 1] = 0;

		if (strlen(buf) > 0) {
			if (strncmp(buf, "--- END", 7) == 0)
				break;
			else
			if (strncmp(buf, "---", 3) == 0)
				continue;

			vals = split_line_by_number_of_chars(buf, 8);
			ret += vals.numVals;
		}
	}
	fclose(fp);

	return ret;
}

tAKDKeyPair akd_read_file(char *filename, tAKDKeyPair kp)
{
	int i, idx, num;
	int dtype = 0;
	FILE *fp = NULL;
	char buf[100] = { 0 };
	tAKDKeyPair ret;
	tTokenizerU64 vals;

	if (access(filename, R_OK) != 0)
		return AKD_KEYPAIR_EMPTY;

	idx = 0;
	if (kp.num == 0) {
		num = akd_get_number_of_elements(filename);
		if (num <= 0)
			return AKD_KEYPAIR_EMPTY;

		ret.common = (tAKDCommon *)malloc( num * sizeof(tAKDCommon) );
		ret.vPrivate = (uint64_t *)malloc( num * sizeof(uint64_t) );
		ret.vPublic = (uint64_t *)malloc( num * sizeof(uint64_t) );
		memset(ret.common, 0, num * sizeof(tAKDCommon) );
		memset(ret.vPrivate, 0, num * sizeof(uint64_t) );
		memset(ret.vPublic, 0, num * sizeof(uint64_t) );
		ret.num = num;
	}
	else
		ret = kp;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return AKD_KEYPAIR_EMPTY;
	while (!feof(fp)) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);

		if (strlen(buf) > 0)
			buf[strlen(buf) - 1] = 0;

		if (strlen(buf) > 0) {
			if (strncmp(buf, "--- END", 7) == 0) {
				dtype = 0;
				continue;
			}
			else
			if (strncmp(buf, "---", 3) == 0) {
				if (strncmp(buf, "--- KEY", 7) == 0)
					dtype = 1;
				else
				if (strncmp(buf, "--- GROUP", 9) == 0)
					dtype = 2;
				else
				if (strncmp(buf, "--- PUBLIC", 10) == 0)
					dtype = 3;
				else
				if (strncmp(buf, "--- PRIVATE", 11) == 0)
					dtype = 4;

				idx = 0;
				continue;
			}

			vals = split_line_by_number_of_chars(buf, 8);
			for (i = 0; i < vals.numVals; i++) {
				uint64_t tmpVal = vals.vals[i];

				if (dtype == 1)
					ret.common[idx].p = tmpVal;
				else
				if (dtype == 2)
					ret.common[idx].g = tmpVal;
				else
				if (dtype == 3)
					ret.vPublic[idx] = tmpVal;
				else
				if (dtype == 4)
					ret.vPrivate[idx] = tmpVal;

				idx++;
			}
		}
	}
	fclose(fp);

	return ret;
}

void akd_keypair_dump(tAKDKeyPair kp)
{
	int i;

	if (kp.num == 0)
		return;

	DPRINTF("Dumping %d values ...\n", kp.num);
	for (i = 0; i < kp.num; i++) {
		DPRINTF("KeyPair #%d\n", i);
		DPRINTF("\t    Key value: 0x%08"PRIx64"\t(%16"PRIi64")\n", kp.common[i].p, kp.common[i].p);
		DPRINTF("\t  Group value: 0x%08"PRIx64"\t(%16"PRIi64")\n", kp.common[i].g, kp.common[i].g);
		DPRINTF("\t Public value: 0x%08"PRIx64"\t(%16"PRIi64")\n", kp.vPublic[i], kp.vPublic[i]);
		DPRINTF("\tPrivate value: 0x%08"PRIx64"\t(%16"PRIi64")\n", kp.vPrivate[i], kp.vPrivate[i]);
	}
}

tAKDData akd_process_data(tAKDParams akd_params)
{
	tAKDData ret = AKD_DATA_EMPTY;

	if (akd_params.step == 1) {
		tAKDKeyPair kp, kpNew;
		char tmp[4096] = { 0 };
		char tmpPrivate[4096] = { 0 };
		char tmpPublic [4096] = { 0 };

		if (akd_params.type == MINCRYPT_FLAG_DHVAL_SENDER) {
			kp = akd_generate_keypair(akd_params.count, NULL);
			snprintf(tmp, sizeof(tmpPrivate), "%s.common", akd_params.filename);
			akd_write_file(tmp, kp, MINCRYPT_FLAG_DHKEY_COMMON);
			snprintf(tmpPrivate, sizeof(tmpPrivate), "%s.privateS", akd_params.filename);
			snprintf(tmpPublic,  sizeof(tmpPublic), "%s.publicS" , akd_params.filename);
		}
		else {
			snprintf(tmp, sizeof(tmpPrivate), "%s.common", akd_params.filename);
			if (access(tmp, R_OK) != 0)
				return ret;
			kp = akd_read_file(tmp, AKD_KEYPAIR_EMPTY);
			kpNew = akd_generate_keypair(kp.num, kp.common);
			akd_keypair_free(kp);
			kp = kpNew;

			ret.bfilename_common = strdup(tmp);
			ret.bfilename_common_size = get_file_size(ret.bfilename_common);

			snprintf(tmpPrivate, sizeof(tmpPrivate), "%s.privateR", akd_params.filename);
			snprintf(tmpPublic,  sizeof(tmpPublic),  "%s.publicR" , akd_params.filename);
		}
		akd_write_file(tmpPrivate, kp, MINCRYPT_FLAG_DHKEY_PRIVATE);
		akd_write_file(tmpPublic, kp, MINCRYPT_FLAG_DHKEY_PUBLIC);
		akd_keypair_free(kp);

		ret.bfilename_private = NULL;
		ret.bfilename_private_size = 0;
		ret.bfilename_public  = NULL;
		ret.bfilename_public_size = 0;
		ret.afilename_common  = strdup(tmp);
		ret.afilename_private = strdup(tmpPrivate);
		ret.afilename_public  = strdup(tmpPublic);
		ret.afilename_common_size = get_file_size(ret.afilename_common);
		ret.afilename_private_size = get_file_size(ret.afilename_private);
		ret.afilename_public_size = get_file_size(ret.afilename_public);
		ret.step = 1;
		ret.direction = akd_params.type;
	}
	else
	if (akd_params.step == 2) {
		char tmp[4096] = { 0 };
		tAKDKeyPair kp;

		free(ret.bfilename_common); ret.bfilename_common = NULL; ret.bfilename_common_size = 0;
		free(ret.bfilename_private); ret.bfilename_private = NULL; ret.bfilename_private_size = 0;
		free(ret.bfilename_public); ret.bfilename_public = NULL; ret.bfilename_public_size = 0;

		snprintf(tmp, sizeof(tmp), "%s.common", akd_params.filename);
		ret.bfilename_common = strdup(tmp);
		ret.bfilename_common_size = get_file_size(tmp);
		kp = akd_read_file(tmp, AKD_KEYPAIR_EMPTY);
		snprintf(tmp, sizeof(tmp), "%s.public%c", akd_params.filename,
			(akd_params.type == MINCRYPT_FLAG_DHVAL_SENDER) ? 'R' : 'S');
		ret.bfilename_public = strdup(tmp);
		ret.bfilename_public_size = get_file_size(tmp);
		kp = akd_read_file(tmp, kp);
		snprintf(tmp, sizeof(tmp), "%s.private%c", akd_params.filename,
			(akd_params.type == MINCRYPT_FLAG_DHVAL_SENDER) ? 'S' : 'R');
		ret.bfilename_private = strdup(tmp);
		ret.bfilename_private_size = get_file_size(tmp);
		kp = akd_read_file(tmp, kp);

		akd_write_file(akd_params.filename, kp, MINCRYPT_FLAG_DHKEY_PRIVATE);
		snprintf(tmp, sizeof(tmp), "%s.pub", akd_params.filename);
		akd_write_file(tmp, kp, MINCRYPT_FLAG_DHKEY_COMMON_P | MINCRYPT_FLAG_DHKEY_PUBLIC);
		akd_keypair_free(kp);

		free(ret.afilename_common); ret.afilename_common = NULL; ret.afilename_common_size = 0;
		ret.afilename_private = strdup(akd_params.filename);
		ret.afilename_private_size = get_file_size(akd_params.filename);
		ret.afilename_public  = strdup(tmp);
		ret.afilename_public_size = get_file_size(tmp);
		ret.step = 2;
		ret.direction = akd_params.type;
	}
	else
	if ((akd_params.step == 3) || (akd_params.step == 4)) {
		int i;
		char tmp[4096] = { 0 };

		tAKDKeyPair kp;

		kp = akd_read_file(akd_params.filename, AKD_KEYPAIR_EMPTY);
		snprintf(tmp, sizeof(tmp), "%s.pub", akd_params.filename);
		kp = akd_read_file(tmp, kp);

		free(ret.bfilename_common); ret.bfilename_common = NULL; ret.bfilename_common_size = 0;
		free(ret.bfilename_private); ret.bfilename_private = NULL; ret.bfilename_private_size = 0;
		free(ret.bfilename_public); ret.bfilename_public = NULL; ret.bfilename_public_size = 0;

		ret.bfilename_private = strdup(akd_params.filename);
		ret.bfilename_public  = strdup(tmp);

		ret.bfilename_private_size = get_file_size(akd_params.filename);
		ret.bfilename_public_size = get_file_size(tmp);

		DPRINTF("Dumping %d values:\n", kp.num);
		ret.vals = (uint64_t *)malloc( kp.num * sizeof(uint64_t) );
		for (i = 0; i < kp.num; i++) {
			uint64_t val = pow_and_mod(kp.vPublic[i], kp.vPrivate[i], kp.common[i].p);
			unsigned char *tmp = uint64_to_binary(val, 32);
			DPRINTF("\t%06d) 0x%08"PRIx64"  (%16"PRIi64", %s)\n", i, val, val, tmp);
			free(tmp); tmp = NULL;

			ret.vals[i] = val;
		}

		ret.num = kp.num;
		free(ret.afilename_common); ret.afilename_common = NULL; ret.afilename_common_size = 0;
		free(ret.afilename_private); ret.afilename_private = NULL; ret.afilename_private_size = 0;
		free(ret.afilename_public); ret.afilename_public = NULL; ret.afilename_public_size = 0;
		ret.step = akd_params.step;
		ret.direction = akd_params.type;

		if (ret.step == 4)
			akd_process_data_dump_keys(ret);

		akd_keypair_free(kp);
	}

	if (ret.step > 0)
		DPRINTF("DH Step %d completed successfully.\n", ret.step);

	return ret;
}

void akd_process_data_dump(tAKDData data)
{
	DPRINTF("Dumping data:\n");
	DPRINTF("\tStep: %d/%s\n", data.step, (data.direction == MINCRYPT_FLAG_DHVAL_RECEIVER) ? "Receiver" :
			((data.direction == MINCRYPT_FLAG_DHVAL_SENDER) ? "Sender" : "Unknown"));
	DPRINTF("\tNumber of values: %d\n", data.num);
	DPRINTF("\tFilenames before:\n");
	DPRINTF("\t\tCommon values: %s (%ld bytes)\n", data.bfilename_common ? data.bfilename_common : "<none>",
				data.bfilename_common_size );
	DPRINTF("\t\t Private keys: %s (%ld bytes)\n", data.bfilename_private ? data.bfilename_private : "<none>",
				data.bfilename_private_size );
	DPRINTF("\t\t  Public keys: %s (%ld bytes)\n", data.bfilename_public ? data.bfilename_public : "<none>",
				data.bfilename_public_size );
	DPRINTF("\tFilenames after:\n");
	DPRINTF("\t\tCommon values: %s (%ld bytes)\n", data.afilename_common ? data.afilename_common : "<none>",
				data.afilename_common_size );
	DPRINTF("\t\t Private keys: %s (%ld bytes)\n", data.afilename_private ? data.afilename_private : "<none>",
				data.afilename_private_size );
	DPRINTF("\t\t  Public keys: %s (%ld bytes)\n", data.afilename_public ? data.afilename_public : "<none>",
				data.afilename_public_size );
}

void akd_process_data_dump_keys(tAKDData data)
{
	int i;

	if (data.num == 0)
		return;

	printf("Dumping keys:\n");
	for (i = 0; i < data.num; i++)
		printf("%8d) 0x%"PRIx64"\n", i, data.vals[i]);
}

void akd_process_data_free(tAKDData data)
{
	free(data.afilename_common);
	free(data.afilename_private);
	free(data.afilename_public);
	free(data.bfilename_common);
	free(data.bfilename_private);
	free(data.bfilename_public);
	free(data.vals);
}

void akd_keypair_free(tAKDKeyPair kp)
{
	if (kp.num == 0)
		return;

	free(kp.common);
	free(kp.vPrivate);
	free(kp.vPublic);
}

