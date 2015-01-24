#ifndef _BIBA_H_
#define _BIBA_H_

// max message length that can be parsed
#define MAX_MESSAGE_LENGTH 1024*1024

// default message to calc sign
#define DEFAULT_MESSAGE "Some test text"

char* hex2bin(char* raw, int* out_len/*is out param*/, char* field_name);
int hash(unsigned char*indata, int inlen, unsigned char *out, int *outlen);
int maccode(unsigned char*indata, int inlen, unsigned char*key, int key_len, unsigned char *out, int *outlen);

#endif /* _BIBA_H_ */
