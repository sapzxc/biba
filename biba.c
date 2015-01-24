///TODO verbose log divider value (0-disable)
///TODO verbose log table
///TODO verbose out
///TODO out to file
///TODO choose hash and mac algorithm?
///TODO sign file
///TODO check sign


#include <stdio.h>
#include <math.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "biba.h"

/**
 * Create sign:
 *  have hash table like this:
 *  Sk1 Sk2 ... Skt					-> calc hashes from up to down
 *   |   |       |    <- H(Ski)
 *  ... ...     ...
 *   |   |       |
 *  S21 S22 ... S2t
 *   |   |       |
 *   |   |       |    <- H(S2i)
 *   |   |       |
 *  S01 S02 ... S0t
 *
 * 1. upper hashes are on sender side and lower hashes will be send to other side(s)
 * 2. this hashes is general params for digital sign
 * 3. calc hash(Message||counter) = h  -> this is key for next step
 * 4. calc mac-code(h/key/, Sj1), ... mac-code(h/key/, Sjt)
 *    j - level of hahes from table
 * 5. look for same mac codes from given results if does not exists then
 *    counter+=1 and go to step 3
 * 6. send sign with additional data ->   message,<S1,S2>,counter
 *    where S1 and S2 - is hashes that give the same mac code
 *
 * Check sign:
 * here we have set of S0i, signed msg (message,<S1,S2>,counter)
 * 1. calc hash(Message||counter) = h
 * 2. check incoming data: mac-code(h/key/, S1) == mac-code(h/key/, S2) must be true
 * 2. calc given S1 and S2 by hash chains up to null level hashes (S0i)
 * 3. and look for given null level hashes in stored vector of hashes (S01 S02 ... S0t)
 * 4. if last level is true then sign true
 *
 * Summary:
 *  - So the Ski vector from table with hashes must be secret for sender side
 *    and public vector is S0i for check sign.
 *  - In each side must be used same hash and mac algirithms with same length of in and out.
 */

char* hex2bin(char* raw, int* out_len/*is out param*/, char* field_name)
{
	// check raw string
    int i;
	char hex_allowed[]="0123456789abcdef";
	for(i=0; i<strlen(raw); i++)
	{
        raw[i]=tolower(raw[i]);
		if(!strchr((const char*)hex_allowed, (char)raw[i]))
		{
			if(field_name>0)
			{
				fprintf(stderr, "Error: \"%s\" must contain only \"%s\" characters!\n", field_name, hex_allowed);
			}
			return (char*)0;
		}
	}

	// convert to bin
	*out_len=ceil(strlen(raw)/2);
	char *out=(char*)malloc((*out_len + 1)  * sizeof(char));
	memset(out, 0, *out_len);
	for(i=0; i<ceil(strlen(raw)/2); i++)
	{
		out[i]=(strchr(hex_allowed,raw[i*2])-hex_allowed & 0xf)<<4;
		if(strlen(raw) >= i*2+1)
		{
			out[i]|=strchr(hex_allowed,raw[i*2+1])-hex_allowed & 0xf;
		}
	}
	return out;
}

/**
 * return hash of given data
 * if (char*)out is null then you give only outlen result
 * @param	indata(unsigned char*)	- in data
 * @param	inlen(int)				- in data len
 * @param	out(char*)				- out data, hash
 * @param	outlen(int*)			- here out data length
 * @return	(bool)					- true if hash calculated
 */
int hash(unsigned char*indata, int inlen, unsigned char *out, int *outlen)
{
	*outlen = MD5_DIGEST_LENGTH;
	if(!out){return 0;}
	MD5(indata,inlen,out);
	return 1;
}

/**
 * return hash of given data
 * if (char*)out is null then you give only outlen result
 * @param	indata(unsigned char*)	- in data
 * @param	inlen(int)				- in data len
 * @param	key(unsigned char*)		- in key
 * @param	key_len(int)			- in key len
 * @param	out(char*)				- out data, hash
 * @param	outlen(int*)			- here out data length
 * @return	(bool)					- true if hash calculated
 */
int maccode(unsigned char*indata, int inlen, unsigned char*key, int key_len, unsigned char *out, int *outlen)
{
	*outlen = MD5_DIGEST_LENGTH;
	if(!out){return 0;}
	HMAC(EVP_md5(), key, key_len, (const unsigned char*)indata, inlen, (unsigned char*)out, (unsigned int*)outlen);
	return 1;
}

/**
 * Find argument by prefix and return pointer
 */
char *findarg(char* prearg, char *prearg_long, int argc, char** argv)
{
    int prearg_len = prearg ? strlen((char*)prearg) : 0;
    int prearg_long_len = prearg_long ? strlen((char*)prearg_long) : 0;
    if(argc < 2 || (!prearg_len && !prearg_long_len)) { return (char*)0; }

    int i;
    for(i=1; i<argc; i++)
    {
        if(prearg_len > 0 && !strncmp(argv[i], prearg, prearg_len))
        {
            if(strlen(argv[i]) > prearg_len)
            {
                return (char*)(argv[i]+prearg_len);
            }
            else if(argc > i+1)
            {
                return (char*)argv[i+1];
            }
            else
            {
                return (char*)(argv[i]+prearg_len);
            }
        }
        else if(prearg_long_len > 0 && !strncmp(argv[i], prearg_long, prearg_long_len))
        {
            if(strlen(argv[i]) > prearg_long_len)
            {
                return (char*)(argv[i]+prearg_long_len);
            }
            else if(argc > i+1)
            {
                return (char*)argv[i+1];
            }
            else
            {
                return (char*)(argv[i]+prearg_len);
            }
        }
    }
    return (char*)0;
}

int main(int argc, char** argv)
{
    // show help
    if(findarg("-h", "--help", argc, argv) || findarg("-?", 0, argc, argv))
    {
        // show usage
        printf("BiBa protocol realisation. Developed by Sap <sap@xprogs.org>\n");
        printf("Version: 03.02.2010\n");
        printf("Use: %s [OPTIONS]\n", argv[0]);
        printf("example: %s -mmessage \n", argv[0]);
        printf("\nAvaliable options:\n" \
                "  -m, --message=<msg>          Message to sign\n" \
                "  -f, --message-file=<path>    Retrive message from this file(are prior than -m option).\n" \
                "                               Note: It read no more than %d bytes from file.\n" \
                "  -i, --init-variant=<num>     Init vector variant. Pass 0(null) for use random values and\n" \
                "                               use any number as start value for first hash(other hashes will\n" \
                "                               take incremental values as input data). Default is 0(null).\n" \
                "  -c, --cols=<num>             Hash count by line (columns). Minimun is 2. Default is 13.\n" \
                "  -r, --rows=<num>             Hash lines count (rows). Minimun is 3. default is 3.\n" \
                "  -H, --hash-width=<num>       Hash results width in bytes. Use range [1;16] for MD5.\n" \
                "  -M, --mac-width=<num>        Mac code results width in bytes. Use range [1;16] for MD5.\n" \
                "  -l, --level=<num>            Hash level to parse. Default is 1. First(=0) and last(=rows)\n" \
                "                               levels can't be used for process.\n" \
                "  -v, --verbose                Verbose output.\n" \
                "  -n, --no-process             Disable process output in verbose mode.\n" \
                "  -h, -?, --help               Show this help\n" \
                "\n", MAX_MESSAGE_LENGTH);
        return 0;
    }

    if(argc < 2)
    {
        fprintf(stderr, "Note: Type %s -? for help of use\n", argv[0]);
    }

    // assign message
	char _message[]=DEFAULT_MESSAGE;
	char *message=findarg("-m", "--message=", argc, argv);
    int message_len = message ? strlen(message) : 0;
    char *message_file=findarg("-f", "--message-file=", argc, argv);
    char message_file_readed=0;
    if(message_file)
    {
        FILE *f=fopen(message_file, "r");
        if(f)
        {
            struct stat st;
            if(stat(message_file, &st))
            {
                fprintf(stderr, "Can't get file info from path \"%s\".\n", message_file);
            }
            else
            {
                int size = st.st_size;
                if(size > MAX_MESSAGE_LENGTH)
                {
                    size = MAX_MESSAGE_LENGTH;
                }
                char *msg=(char*)malloc(size);
                message_file_readed=1;
                message_len=fread(msg, 1, size, f);
                message=msg;
                if(message_len != size)
                {
                    fprintf(stderr, "Warning: Readed %d bytes but requested %d bytes for read.\n", message_len, size);
                }
                fclose(f);
            }
        }
        else
        {
            fprintf(stderr, "Can't read file \"%s\".\n", message_file);
        }
    }
    if(!message)
    {
        fprintf(stderr, "Message is not defined. Use default message: \"%s\"\n", _message);
        message=(char *)&_message;
        message_len = strlen(message);
    }

    // init
    srand((unsigned int)time(0));

	int hash_by_line  = 13; // 2 minimum
	int hash_levels   = 3;  // 3 minimum
	int hash_len	  = 2; // hash length used for hash table
	int mac_len		  = 2; // mac code length used for results
    int use_hash_level      = 1; // can't be first or last row
    int init_vector_variant = 0; // init vector create principle (=0 random, >0 incremental)
    int verbose             = 0; // verbose output
    int verbose_no_process  = 0; // verbose no process

    // get hash length
    int hash_len_max = 0; // real hash length
    hash(0, 0, 0, &hash_len_max); // get hash length

    // get mac code length
    int mac_len_max=0;
    maccode(0,0,0,0,0, &mac_len_max);

    char *tmp_num;

    // assign init_vector principle
    tmp_num = findarg("-i", "--init-variant=", argc, argv);
    if(tmp_num)
    {
        init_vector_variant = atoi(tmp_num);
        if(!init_vector_variant)
        {
            printf("Used random principle for fill init vector\n");
        }
        else
        {
            printf("Used %d value as start iteration value for init vector.\n",
                    init_vector_variant);
        }
    }

    tmp_num = findarg("-c", "--cols=", argc, argv);
    if(tmp_num) { hash_by_line = atoi(tmp_num); }
    if(hash_by_line < 2)
    {
        fprintf(stderr, "Error: Cols value is too small \"%d\"\n", hash_by_line);
        hash_by_line=2;
    }

    tmp_num = findarg("-r", "--rows=", argc, argv);
    if(tmp_num) { hash_levels = atoi(tmp_num); }
    if(hash_levels < 3)
    {
        fprintf(stderr, "Error: Rows value is too small \"%d\"\n", hash_levels);
        hash_levels=3;
    }

    tmp_num = findarg("-H", "--hash-width=", argc, argv);
    if(tmp_num) { hash_len = atoi(tmp_num); }
    if(hash_len < 1)
    {
        fprintf(stderr, "Error: Hash width value is too small \"%d\"\n", hash_len);
        hash_len=1;
    }
    if(hash_len > hash_len_max)
    {
        fprintf(stderr, "Error: Hash width value is too big \"%d\"\n", hash_len);
        hash_len=hash_len_max;
    }

    tmp_num = findarg("-M", "--mac-width=", argc, argv);
    if(tmp_num) { mac_len = atoi(tmp_num); }
    if(mac_len < 1)
    {
        fprintf(stderr, "Error: Mac-code width value is too small \"%d\"\n", mac_len);
        mac_len=1;
    }
    if(mac_len > mac_len_max)
    {
        fprintf(stderr, "Error: Mac-code width value is too big \"%d\"\n", mac_len);
        mac_len=mac_len_max;
    }

    tmp_num = findarg("-l", "--level=", argc, argv);
    if(tmp_num) { use_hash_level = atoi(tmp_num); }
    if(use_hash_level < 1)
    {
        fprintf(stderr, "Error: Hash level is too small \"%d\"\n", mac_len);
        use_hash_level=1;
    }

    if(use_hash_level >= hash_levels)
    {
        fprintf(stderr, "Error: Hash level is too big \"%d\". It can't be bigger than (rows-1) value.\n", mac_len);
        use_hash_level=hash_levels-1;
    }

    tmp_num = findarg("-v", "--verbose", argc, argv);
    if(tmp_num) { verbose=1; }

    tmp_num = findarg("-n", "--no-process", argc, argv);
    if(tmp_num) { verbose_no_process=1; }

    if(verbose)
    {
        printf("Hash table cols  : %d\n", hash_by_line);
        printf("Hash table rows  : %d\n", hash_levels);
        printf("Hash result width: %d\n", hash_len);
        printf("Mac result width : %d\n", mac_len);
        printf("Parse row number : %d\n", use_hash_level);
        printf("\n");
    }


    /** *****************************************************************************************
     *  Start process
     */
	unsigned char **vector_sender;	 // here will be pointer to sender hash line
	unsigned char **vector_receiver; // here will be pointer to receiver hash line (S01 S02 ... S0t)

	// create hash table
    if(verbose){printf("Hash table:\nLevel%d = ", (hash_levels-1));}
	unsigned char ***hash_tb = (unsigned char***)malloc(hash_levels * sizeof(unsigned char**));
	unsigned char *tmp_hash  = (unsigned char*)malloc(hash_len_max * sizeof(unsigned char));

	int j=hash_levels-1;
	hash_tb[j] = (unsigned char**)malloc(hash_by_line * sizeof(unsigned char*));
    int i=0;
	for(i=0; i<hash_by_line; i++)
	{
		hash_tb[j][i]=(unsigned char*)malloc(hash_len * sizeof(unsigned char));

        int rnd;
        if(!init_vector_variant)
        {
            rnd=rand();
        }
        else
        {
            rnd=i+init_vector_variant;
        }

		hash((unsigned char*)&rnd, sizeof(int), tmp_hash, &hash_len_max);
		memcpy(hash_tb[j][i], tmp_hash, hash_len);

        if(verbose)
        {
            int e;
            for(e=0; e<hash_len; e++) {printf("%02x", hash_tb[j][i][e]);}printf(" ");
        }
	}
	if(verbose)printf("\n");

	for(j=hash_levels-2; j>=0; j--)
	{
        if(verbose){printf("Level%d = ", j);}
		hash_tb[j] = (unsigned char**)malloc(hash_by_line * sizeof(unsigned char*));
		for(i=0; i<hash_by_line; i++)
		{
			hash_tb[j][i]=(unsigned char*)malloc(hash_len * sizeof(unsigned char));
			hash(hash_tb[j+1][i], hash_len, tmp_hash, &hash_len_max);
			memcpy(hash_tb[j][i], tmp_hash, hash_len);

            if(verbose)
            {
                int e;
                for(e=0; e<hash_len; e++) {printf("%02x", hash_tb[j][i][e]);}printf(" ");
            }
		}
		if(verbose)printf("\n");
	}
	free(tmp_hash);
    if(verbose)printf("\n");

	vector_receiver = hash_tb[0];
	vector_sender   = hash_tb[use_hash_level];

	// find same S1 and S2

	// create macs array
	unsigned char *tmp_mac = (unsigned char*)malloc(mac_len_max * sizeof(unsigned char));

	unsigned int macs_len= hash_by_line;
	unsigned char **macs = (unsigned char**)malloc(macs_len * sizeof(unsigned char*));
	for(i=0; i<macs_len ; i++)
	{
		macs[i]=(unsigned char*)malloc(mac_len * sizeof(unsigned char));
	}

	// create h/key/
	unsigned int h_len=hash_len_max;
	unsigned char *h  =(unsigned char*)malloc(h_len * sizeof(unsigned char));

	unsigned long long counter=0;
    unsigned long long counter_max=(unsigned long long)-1;
	int found=0;
	int found_s1=0;
	int found_s2=0;

    int msg_counter_len=message_len + sizeof(counter);
    unsigned char *msg_counter=(unsigned char*)malloc(msg_counter_len * sizeof(unsigned char));

	while(!found)
	{
		// calc single mac codes vector

		// calc mac code key
		memcpy((char*)msg_counter, (char*)message, message_len);
		memcpy((char*)(msg_counter+message_len), (char*)&counter, sizeof(counter));
		hash(msg_counter, msg_counter_len, h, &hash_len_max);

		// calc mac codes vector
		for(i=0; i<macs_len ; i++)
		{
			maccode(vector_sender[i], hash_len, //in
					h, h_len,	// key
					tmp_mac, &mac_len_max); // out
			memcpy(macs[i], tmp_mac, mac_len);
		}

		// look for same macs
		for(j=0; j<macs_len-1 && !found; j++)
		{
			for(i=j+1; i<macs_len && !found; i++)
			{
				if( memcmp(macs[j], macs[i], mac_len) == 0 )
				{
					if( memcmp(vector_sender[j], vector_sender[i], hash_len) != 0 )
					{
						found_s1=j;
						found_s2=i;
						found=1;
					}
				}
			}
		}

		if(!found)
		{
            if(counter == counter_max)
            {
                fprintf(stderr, "Message salt (integer iterator) rish to max value 2^%d. Break process.\n", sizeof(counter)*8);
                break;
            }
			counter++;
			if(verbose && !verbose_no_process && counter % (hash_by_line*50) == 0)
			{
                if(counter <= hash_by_line*50)
                {
                    printf("Finding process:\n");
                }
				printf("counter = %lld, macs: ", counter);
				for(i=0; i<macs_len; i++)
				{
                    int e;
					for(e=0; e<mac_len; e++) {printf("%02x", macs[i][e]);}printf(" ");
				}
				printf("\n");
			}
		}
	}
    free(msg_counter);

    if(found)
    {
        int e;
        if(verbose)
        {
            printf("\nFinished!\nmac(key, ");
            for(    e=0; e<hash_len; e++) {printf("%02x", vector_sender[found_s1][e]);}
            printf(") = mac(key, ");
            for(    e=0; e<hash_len; e++) {printf("%02x", vector_sender[found_s2][e]);}
            printf(") = ");
            for(e=0; e<mac_len; e++) {printf("%02x", macs[found_s1][e]);}
            printf(". Reached on %lld loop.\n", counter);
        }

        printf("\ninput parameters:\n");
        printf("Hash table cols  : %d\n", hash_by_line);
        printf("Hash table rows  : %d\n", hash_levels);
        printf("Hash result width: %d\n", hash_len);
        printf("Mac result width : %d\n", mac_len);
        printf("Parse row number : %d\n", use_hash_level);
        printf("Init vect variant: ");
        if(!init_vector_variant)
        {
            printf("random");
        }
        else
        {
            printf("%d value", init_vector_variant);
        }
        printf("\n");

        // out vector
        if(verbose)
        {
            printf("Init vector      : ");
            int j=hash_levels-1;
            int i=0;
            for(i=0; i<hash_by_line; i++)
            {
                for(e=0; e<hash_len; e++) {printf("%02x", hash_tb[j][i][e]);}printf(" ");
            }
        }

        printf("\nresults:\ns1  : ");
        for(	e=0; e<hash_len; e++) {printf("%02x", vector_sender[found_s1][e]);}printf(" ");
        printf("\ns2  : ");
        for(    e=0; e<hash_len; e++) {printf("%02x", vector_sender[found_s2][e]);}printf(" ");
        printf("\nmac : ");
        for(e=0; e<mac_len; e++) {printf("%02x", macs[found_s1][e]);}printf(" ");
        printf("\ncounter : %lld\n", counter);
    }
    else
    {
        printf("The same macs didn't found. Try change input parameters for take effect.\n");
    }

    // if message loaded from file, then free message memory
    if(message_file_readed)
    {
        free(message);
    }

	// remove macs array
	for(i=0; i<macs_len ; i++)
	{
		free(macs[i]);
	}
	free(macs);
	free(tmp_mac);

	// remove hash
	free(h);

	// remove hash table
	for(j=0; j<hash_levels; j++)
	{
		for(i=0; i<hash_by_line; i++)
		{
			free(hash_tb[j][i]);
		}
		free(hash_tb[j]);
	}
	free(hash_tb);

	return 0;
}
