/*
*  mincrypt-main.c: Minimalistic encryption system application
*
*  Copyright (c) 2010-2012, Michal Novotny <mignov@gmail.com>
*  All rights reserved.
*
*  See COPYING for the license of this software
*
*/

#include "mincrypt.h"

#ifndef DISABLE_DEBUG
#define DEBUG_MINCRYPT_MAIN
#endif

#ifdef DEBUG_MINCRYPT_MAIN
#define DPRINTF(fmt, ...) \
do { fprintf(stderr, "[mincrypt/main        ] " fmt , ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
do {} while(0)
#endif

tAKDParams akd_params;

char *infile		= NULL;
char *outfile		= NULL;
char *salt		= NULL;
char *type		= NULL;
char *keyfile		= NULL;
char *dump_file 	= NULL;
int vector_mult		= -1;
int keysize		= 0;
int decrypt		= 0;
int simple_mode 	= 0;
int use_four_bs 	= 0;
unsigned char *password = NULL;

int parseArgs(int argc, char * const argv[]) {
long ver;
int option_index = 0, c;
struct option long_options[] = {
	{"input-file", 1, 0, 'i'},
	{"output-file", 1, 0, 'o'},
	{"password", 1, 0, 'p'},
	{"salt", 1, 0, 's'},
	{"decrypt", 0, 0, 'd'},
	{"type", 1, 0, 't'},
	{"simple-mode", 0, 0, 'm'},
		{"vector-multiplier", 1, 0, 'v'},
		{"key-size", 1, 0, 'k'},
		{"key-file", 1, 0, 'f'},
		{"dump-vectors", 1, 0, 'u'},
		{"version", 0, 0, 'e'},
		{"akd-step", 1, 0, 'a'},
		{0, 0, 0, 0}
	};

	char *optstring = "i:o:a:p:s:v:k:u:de";

	while (1) {
		c = getopt_long(argc, argv, optstring,
			long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'i':
				infile = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			case 's':
				salt = optarg;
				break;
			case 't':
				type = optarg;
				break;
			case 'm':
				simple_mode = 1;
				break;
			case 'd':
				decrypt = 1;
				break;
			case 'k':
				keysize = atoi(optarg);
				if (keysize < 128)
					return 1;
				break;
			case 'f':
				keyfile = optarg;
				break;
			case 'u':
				dump_file = optarg;
				break;
			case 'e':
				ver = mincrypt_get_version();
				printf("Using library version %d.%d.%d\n", (int)((ver >> 16) & 0xFF),
							(int)((ver >> 8 & 0xFF)), (int)(ver & 0xFF));
				break;
			case '4':
				use_four_bs = 1;
				break;
			case 'a':
				akd_params = akd_parse_value(optarg);
				break;
			case 'q':
				if (!mincrypt_set_four_system_quartet(optarg))
					printf("Warning: Cannot set four base system quartet to %s\n", optarg);
				break;
			case 'v':
				vector_mult = atoi(optarg);
				if (vector_mult < 32)
					return 1;
		}
	}

	return ((((infile != NULL) && (outfile != NULL)) || ((keyfile != NULL) && (keysize > 0)) || (akd_params.step > 0)) ? 0 : 1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int isPrivate = 0;
	tAKDData akd = AKD_DATA_EMPTY;

	mincrypt_init();

	if (parseArgs(argc, argv)) {
		printf("%s v%s\n", MINCRYPT_BANNER, PACKAGE_VERSION);
		printf("\nSyntax: %s --input-file=infile --output-file=outfile [--decrypt] [--password=pwd] [--salt=salt]\n"
			"\t\t[--vector-multiplier=number] [--type=base64|binary] [--simple-mode] [--key-size <keysize>\n"
			"\t\t--key-file <keyfile-prefix>] [--dump-vectors <dump-file>] [--version] [--dh-step <value>]\n",
				argv[0]);

		printf("\n");
		printf("The --dh-step option is determining step for Diffie-Hellman like encryption system. The <value> should be\n");
		printf("in the \"<type>:<step>:<file>[:count]\" format. Count is applicable only for step 1 and it  will specify how\n");
		printf("many values to generate - i.e. the length of the key. The <type> value can be either s (or Sender) or r (or\n");
		printf("Receiver) and the <step> can be one of following values:\n\n");
		printf("\t1\t- generate common, private and public key parts (in <file> and <file>.pub files)\n");
		printf("\t2\t- generate private and public values using common information from file <file>\n");
		printf("\nBy common information/values the key value \"p\" and group value \"g\" are meant.\n");
		return 1;
	}

	if (akd_params.step > 0) {
		DPRINTF("DHParams = { type: %s, step: %d, count: %d, filename: %s }\n",
				(akd_params.type == MINCRYPT_FLAG_DHVAL_RECEIVER) ? "Receiver" : 
				((akd_params.type == MINCRYPT_FLAG_DHVAL_SENDER) ? "Sender" : "Unknown"),
				akd_params.step, akd_params.count, akd_params.filename);
		akd = akd_process_data(akd_params);

		if ((akd_params.step < 3) || (akd.num == 0)) {
			int ret = (akd.num == 0) ? 1 : 0;
			akd_process_data_dump(akd);
			akd_process_data_free(akd);
			if (ret == 1)
				fprintf(stderr, "Error: Number of keys found is zero!\n");
			return ret;
		}
	}

	if (password == NULL) {
		/* This means we don't use DH-like encryption */
		if (akd.step == -1) {
			char *tmp;

			if (salt == NULL)
				salt = DEFAULT_SALT_VAL;

			tmp = getpass("Enter password value: ");
			if (tmp == NULL) {
				printf("Error: No password entered\n");
				return 1;
			}
			password = strdup(tmp);
			free(tmp);
		}
		else {
			int i, j;
			password = (unsigned char *)malloc( ((akd.num * 8) + 1) * sizeof(unsigned char) );
			memset(password, 0, ((akd.num * 8) + 1) * sizeof(unsigned char) );

			for (i = 0; i < akd.num; i++) {
				unsigned char *ret = uint64_to_bytes(akd.vals[i], 4);
				for (j = 0; j < 4; j++) {
					char tmpx[3] = { 0 };
					snprintf(tmpx, sizeof(tmpx), "%02x", ret[j]);

					strcat(password, tmpx);
				}
				free(ret); ret = NULL;
			}

			DPRINTF("Asymmetric key exchange used. Password: %s\n", password);

			uint32_t tmp = crc32_block(password, strlen(password), 0xFFFFFFFF);
			char tmpS[32] = { 0 };
			snprintf(tmpS, sizeof(tmpS), "%"PRIx64, tmp);
			salt = strdup(tmpS);

			if (akd_params.step == 4) {
				printf("Asymmetric key resulted into password: %s (salt is %s)\n", password, salt);
				free(password);
				free(salt);
				akd_process_data_free(akd);

				return 0;
			}
		}
	}

	/* Process read handler for password */
	if (strncmp(password, "read://", 7) == 0) {
		int fd, size = -1;
		char *fn = password + 7;

		if (access(fn, R_OK) != 0) {
			DPRINTF("Cannot read password file '%s'\n", fn);
			return 1;
		}

		fd = open(fn, O_RDONLY);
		size = lseek(fd, 0, SEEK_END);

		lseek(fd, 0, SEEK_SET);
		password = (char *)malloc( size * sizeof(char) );
		if (read(fd, password, size) <= 0) {
			DPRINTF("Cannot read the data from file '%s'\n", fn);
			return 1;
		}
		close(fd);
	}

	/* Use base 4 numbering system for password and salt encoding */
	if (use_four_bs == 1) {
		unsigned char *tmp1 = NULL;

		tmp1 = mincrypt_convert_to_four_system((unsigned char *)salt, strlen(salt));
		salt = strdup((char *)tmp1);
		free(tmp1);

		tmp1 = mincrypt_convert_to_four_system((unsigned char *)password, strlen(password));
		password = strdup((char *)tmp1);
		free(tmp1);
	}

	if (keysize > 0) {
		int ret;
		char public_key[4096] = { 0 };
		char private_key[4096] = { 0 };

		snprintf(private_key, sizeof(private_key), "%s.key", keyfile);
		snprintf(public_key, sizeof(public_key), "%s.pub", keyfile);

		printf("Generating keys based on input data. This may take a while...\n");
		ret = mincrypt_generate_keys(keysize, salt, password, private_key, public_key);
		printf("Key generation done. Keys saved as { private = '%s', public = '%s' }\n",
			private_key, public_key);
		return ret;
	}

	if (keyfile != NULL) {
		int ret;

		if ((ret = mincrypt_read_key_file(keyfile, &isPrivate)) != 0) {
			fprintf(stderr, "Error while reading key file '%s' (error code %d, %s)\n", keyfile, ret, strerror(-ret));
			return 2;
		}

		DPRINTF("Key file %s contains %s key\n", keyfile, isPrivate ? "private" : "public");

		if (isPrivate && !decrypt) {
			fprintf(stderr, "Error: Cannot use private key for encryption\n");
			return 3;
		}

		if (!isPrivate && decrypt) {
			fprintf(stderr, "Error: Cannot use public key for decryption\n");
			return 3;
		}
	}

	if ((type != NULL) && (strcmp(type, "base64") == 0))
		if (mincrypt_set_encoding_type(ENCODING_TYPE_BASE64) != 0)
			printf("Warning: Cannot set base64 encoding, using binary encoding instead\n");

	if (simple_mode)
		if (mincrypt_set_simple_mode(1) != 0)
			printf("Warning: Cannot set simple mode for non-binary encoding\n");

	if (!decrypt)
		ret = mincrypt_encrypt_file(infile, outfile, password, salt, vector_mult);
	else
		ret = mincrypt_decrypt_file(infile, outfile, password, salt, vector_mult);

	if (dump_file != NULL)
		mincrypt_dump_vectors(dump_file);

	mincrypt_cleanup();
	
	if (ret != 0)
		fprintf(stderr, "Action failed with error code: %d\n", ret);
	else
		printf("Action has been completed successfully\n");

	akd_process_data_dump(akd);
	akd_process_data_free(akd);
	return ret;
}
