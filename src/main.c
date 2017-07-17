#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#define CT_CHANGE_CIPHER_SPEC 0x14
#define CT_ALERT              0x15
#define CT_HANDSHAKE          0x16
#define CT_APPLICATION        0x17

#define STR_SIZE 64

typedef struct {
	unsigned char type;
	unsigned char version[2];
	unsigned char length[2];
	unsigned char hs_type;
	unsigned char hs_length[3];
	unsigned char hs_version[2];
	unsigned char hs_random[32];
}SSLHEADER_t;

typedef struct {
	unsigned char cipher[2];
	unsigned char str[STR_SIZE];
}CIPHER_t;

enum {
        CLIENT_HELLO = 0x1,
        SERVER_HELLO = 0x2,
        NEW_SESSION_TICKET = 0x4,
        SERVER_CERT = 0xB,
        SERVER_KEY_EXCHANGE = 0xC,
        SERVER_HELLO_DONE = 0xE,
        CLIENT_KEY_EXCHANGE = 0x10,
        FINISHED = 0x14,
};

typedef struct {
	unsigned char type;
	unsigned char str[STR_SIZE];
}HandShakeType_t;

HandShakeType_t handshake_type[] = {
	{ CLIENT_HELLO,  "ClientHello"},
	{ SERVER_HELLO,  "ServerHello"},
	{ SERVER_CERT,  "Certificate"},
	{ NEW_SESSION_TICKET,  "New Session Ticket"},
	{ SERVER_KEY_EXCHANGE,  "Server Key Exchange"},
	{ SERVER_HELLO_DONE,  "Server Hello Done"},
	{ CLIENT_KEY_EXCHANGE, "Client Key Exchange"},
	{ FINISHED, "Finished"},
};

CIPHER_t ciphersuites[] = {
	{ 0x00, 0x0a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
	{ 0x00, 0x2f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
	{ 0x00, 0x35, "TLS_RSA_WITH_AES_256_CBC_SHA"},
	{ 0x00, 0x9c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
	{ 0x00, 0x9d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
	{ 0xc0, 0x13, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
	{ 0xc0, 0x14, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
	{ 0xc0, 0x2b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
	{ 0xc0, 0x2c, "TLS_ECHDE_ECDSA_WITH_AES_256_GCM_SHA384"},
	{ 0xc0, 0x2f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
	{ 0xc0, 0x30, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
};

enum HandShake_t {
	TYPE,
	VERSION,
	LENGTH,
	HS_TYPE,
	HS_LENGTH,
	HS_VERSION,
	HS_RANDOM,
	HS_SESSION_ID,
	HS_CIPHER_SUITES,
	HS_CERT_LENGTH,
	FINISH,
};

enum {
	VER_MAJOR_TLS = 0x3,
};

enum {
	VER_MINOR_TLS10 = 0x1,
	VER_MINOR_TLS11 = 0x2,
	VER_MINOR_TLS12 = 0x3,
};

int readVersion(unsigned char *version, int length)
{
	int ret = 0;

	printf("Version: ");
	switch(version[0]) {
		case VER_MAJOR_TLS:
			printf("TLS");
			break;
		default:
			printf("failed to read ssl version\r\n");
			ret = -1;
			goto done;
	}
	switch(version[1]) {
		case VER_MINOR_TLS10:
			printf("1.0");
			break;
		case VER_MINOR_TLS11:
			printf("1.1");
			break;
		case VER_MINOR_TLS12:
			printf("1.2");
			break;
		default:
			printf("Unsupported version\r\n");
			ret = -1;
			break;
	}
	printf(" (0x%02X%02X)\r\n", version[0], version[1]);
done:
	return ret;
}

int calLength(unsigned char *length, int len)
{
	int _length = 0;
	int index = 0;

	_length = length[0];
	for (index = 1; index < len; index++) {
		_length = _length << 8;
		_length += length[index];
	}

	return _length;
}

int readHex(unsigned char *out, int c, int size, FILE *fp)
{
	int shift = 3;
	int index = c*shift, i=0;
	unsigned char *p=out;

	for (i=0; i<size; i++) {
		fread(p, sizeof(unsigned char), shift, fp);
		if (p[2] != ' ') {
			fseek(fp, -1, SEEK_CUR);
			shift = 2;
		}
		p+=2;
	}
	p[size-1]='\0';

	return 0;
}

unsigned char *readHSType(unsigned char type)
{
        int index=0, hs_type_size;
        hs_type_size = sizeof(handshake_type)/sizeof(handshake_type[0]);
        for (index=0; index<hs_type_size; index++) {
                if (handshake_type[index].type == type) {
                        break;
                }
        }

        return handshake_type[index].str;
}

int c2i(char ch)  
{  
	if(isdigit(ch))  
		return ch - 48;  

	if( ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z' )  
		return -1;  

	if(isalpha(ch))  
		return isupper(ch) ? ch - 55 : ch - 87;  

	return -1;  
}  

int hex2dec(char *hex)  
{  
	int len;  
	int num = 0;  
	int temp;  
	int bits;  
	int i;  

	len = strlen(hex);  

	for (i=0, temp=0; i<len; i++, temp=0)  
	{  
		temp = c2i( *(hex + i) );  
		bits = (len - i - 1) * 4;  
		temp = temp << bits;  

		num = num | temp;  
	}  

	return num;  
}

long getFileSize(FILE *fp)
{
	long size = 0;
	int shift = 3;
	unsigned char str[3];

	fseek(fp,0L,SEEK_END);
	size = ftell(fp);
	fseek(fp,0L,SEEK_SET);
	fread(str, sizeof(unsigned char), sizeof(str), fp);
	if (str[2] == ' ') shift = 3;
	else shift = 2;
	size /= shift;
	fseek(fp,0L,SEEK_SET);

	return size;
}

int processType(unsigned char type, int length)
{
	printf("Content Type: ");
	switch(type) {
		case CT_CHANGE_CIPHER_SPEC:
			printf("Change cipher spec");
			break;
		case CT_ALERT:
			printf("Alert");
			break;
		case CT_HANDSHAKE:
			printf("Handshake");
			break;
		case CT_APPLICATION:
			printf("Application");
			break;
		default:
			printf("failed to read ssl type");
			break;
	}

	printf(" (%d)\r\n", type);
	return VERSION;
}

int processVersion(unsigned char *version, int length)
{
	readVersion(version, length);
	return LENGTH;
}

int processLength(SSLHEADER_t *sslheader, int len)
{
	int _length = 0, ret = FINISH;

	_length = calLength(sslheader->length, len);
	printf("Length: %d\r\n", _length);
	switch(sslheader->type) {
	case CT_HANDSHAKE:
		ret = HS_TYPE;
	}
	if (!strcmp(readHSType(sslheader->hs_type), "")) {
		ret = FINISH;
	}

	return ret;
}

int processHStype(unsigned char type, int len)
{
	printf("Handshake Type: ");
	printf("%s (%d)\r\n", readHSType(type), type);
	return HS_LENGTH;
}

int processHSlength(SSLHEADER_t *sslheader, int len)
{
	int _length = 0, ret = HS_VERSION;

	int i=0;
	_length = calLength(sslheader->hs_length, len);
	printf("Length: %d\r\n", _length);

	switch(sslheader->hs_type) {
	case CLIENT_HELLO:
	case SERVER_HELLO:
		ret = HS_VERSION;
		break;
	case SERVER_CERT:
		ret = HS_CERT_LENGTH;
		break;
	default:
		ret = FINISH;
		break;
	}

	return ret;
}

int processHSversion(unsigned char *version, int length)
{
	readVersion(version, length);
	return HS_RANDOM;
}

int processHSrandom(unsigned char *random, int len)
{
	int index=0;

	printf("Random: ");
	for(index=0; index<len; index++) {
		printf("%02X", random[index]);
	}
	printf("\r\n");

	return HS_SESSION_ID;
}

int processHSsessionID(unsigned char **hex, int len)
{
	int index=0;

	printf("Session ID Length: ");
	if (*hex[0] == 0) {
		puts("0");
		*hex+=1;
		goto done;
	}
	for (index=0; index<len; index) {
		printf("%02X", *hex[index]);
	}
	*hex+=32;
done:
	return HS_CIPHER_SUITES;		
}

unsigned char *cipher2str(unsigned char *cipher, int len)
{
	int index=0, suites_size = 0;

	suites_size = sizeof(ciphersuites)/sizeof(ciphersuites[0]);
	for (index=0; index<suites_size; index++) {
		if (cipher[0] == ciphersuites[index].cipher[0] &&
				cipher[1] == ciphersuites[index].cipher[1]) {
			break;
		}
	}
	return ciphersuites[index].str;
}

int processHSciphersuites(SSLHEADER_t *sslheader, unsigned char **hex, int len)
{
	int _length=0, index=0, ret = FINISH;

	if (sslheader->type == CT_HANDSHAKE) {
		switch(sslheader->hs_type) {
		case CLIENT_HELLO:
			_length = calLength(*hex, len);
			printf("Cipher Suites Length: %d\r\n", _length);
			*hex+=len;
			break;
		case SERVER_HELLO:
			_length = 1;
			break;
		}
	}
	for (index=0; index<_length; index++, *hex+=2) {
		printf("Cipher Suites: ");
		printf("%s\r\n", cipher2str(*hex, 2));
	}

	return ret;
}

int processHScertLength(unsigned char **hex, int len)
{
	int _length = 0;
	_length = calLength(*hex, len);
	printf("Certificates Length: %d\r\n", _length);
	*hex+=len;

	return FINISH;
}

int main(int argc, char **argv)
{
	FILE *fp = NULL;
	char input[STR_SIZE];
	int c=0, status = TYPE;
	long size = 0, count=0;
	unsigned char *hex = NULL, *pHex = NULL;
	int index=0;
	SSLHEADER_t *sslheader;


	if (argc < 2) {
		printf("Wrong parameter\r\n");
		return 1;
	}
	strncpy(input, argv[1], sizeof(input));
	if ((fp = fopen(input, "r")) == NULL) {
		fprintf(stderr, "%s: %s\r\n", input, strerror(errno));
	}
	count = getFileSize(fp);

	hex = (unsigned char*)malloc(sizeof(unsigned char)*count);
	for (index=0; index<count; index++) {
		unsigned char text[3];
		unsigned char dec;
		readHex(text, index, 1, fp);
		dec = hex2dec(text);
		hex[index] = dec;
	}
	pHex = hex;
	sslheader = (SSLHEADER_t*)hex;
	while (status != FINISH) {
		switch (status) {
			case TYPE:
				status = processType(sslheader->type, 1);
				pHex+=sizeof(sslheader->type);
				break;
			case VERSION:
				status = processVersion(sslheader->version, 2);
				pHex+=sizeof(sslheader->version);
				break;
			case LENGTH:
				status = processLength(sslheader, 2);
				pHex+=sizeof(sslheader->length);
				break;
			case HS_TYPE:
				status = processHStype(sslheader->hs_type, 1);
				pHex+=sizeof(sslheader->hs_type);
				break;
			case HS_LENGTH:
				status = processHSlength(sslheader, 3);
				pHex+=sizeof(sslheader->hs_length);
				break;
			case HS_VERSION:
				status = processHSversion(sslheader->hs_version, 2);
				pHex+=sizeof(sslheader->hs_version);
				break;
			case HS_RANDOM:
				status = processHSrandom(sslheader->hs_random, 32);
				pHex+=sizeof(sslheader->hs_random);
				break;
			case HS_SESSION_ID:
				status = processHSsessionID(&pHex, 32);
				break;
			case HS_CIPHER_SUITES:
				status = processHSciphersuites(sslheader, &pHex, 2);
				break;
			case HS_CERT_LENGTH:
				status = processHScertLength(&pHex, 3);
				break;
			default:
				printf("Unsupported status\r\n");
				status = FINISH;
				break;
		}
	}
	printf("Data: ");
	for (index=pHex-hex; index<count; index++) {
		printf("%02X ", hex[index]);
	}
	printf("\r\n");
done:
	fclose(fp);
	free(hex);
	return 0;
}

