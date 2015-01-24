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

class hashes
{
private:
	int inMask;
	int outMask;
	int hashLenMax;
	unsigned char *tmpHash;

public:

	hashes(int inMask, int outMask)
	{
		this->inMask = inMask;
		this->outMask = outMask;

		// get hash length
	    hashLenMax = 0; // real hash length
	    this->hashRaw(0, 0, 0, &hashLenMax); // get hash length

	    // create tmp hash
	    tmpHash = (unsigned char*)malloc(hashLenMax * sizeof(unsigned char));
	}

	~hashes()
	{
		free(tmpHash);
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
	int hashRaw(unsigned char*indata, int inlen, unsigned char *out, int *outlen)
	{
		*outlen = MD5_DIGEST_LENGTH;
		if(!out){return 0;}
		MD5(indata,inlen,out);
		return 1;
	}

	int hash(int src)
	{
		src &= inMask;

		int len=0;
		this->hashRaw((unsigned char*)&src, sizeof(int), tmpHash, &len);

		int *h;
		h=(int*)(tmpHash+4);
		*h &= outMask;

		return *h;
	}
};

int bits_count(int x)
{
	int res=0;
	while(x)
	{
		x>>=1;
		res++;
	}
	return res;
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
        printf("Hashed archiver realisation. Developed by Sap <sap@xprogs.org>\n");
        printf("Version: 13.10.2011\n");
        printf("Use: %s [OPTIONS]\n", argv[0]);
        printf("example: %s -mmessage \n", argv[0]);
        printf("\nAvaliable options:\n" \
                "  -H, --hash-width=<num>       Hash results width in bytes. Use range [1;16] for MD5.\n" \
                "  -I, --input-width=<num>      Hahs input width in bits.\n" \
                "  -v, --verbose                Verbose output.\n" \
                "  -h, -?, --help               Show this help\n" \
                "\n", MAX_MESSAGE_LENGTH);
        return 0;
    }
/*
    if(argc < 2)
    {
        fprintf(stderr, "Note: Type %s -? for help of use\n", argv[0]);
		return 0;
    }
*/
    // init
    srand((unsigned int)time(0));

	int hash_len	  = 2; // hash length used for hash table
	int hash_len_max  = 4;
	int input_len	  = 2; // hash input len
	int input_len_max = 48;
    int verbose       = 0; // verbose output

	char* tmp_num;
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

    tmp_num = findarg("-I", "--input-width=", argc, argv);
    if(tmp_num) { input_len = atoi(tmp_num); }
    if(input_len < 1)
    {
        fprintf(stderr, "Error: Input width value is too small \"%d\"\n", input_len);
        input_len=1;
    }
    if(input_len > input_len_max)
    {
        fprintf(stderr, "Error: Input width value is too big \"%d\"\n", input_len);
        input_len=input_len_max;
    }

    tmp_num = findarg("-v", "--verbose", argc, argv);
    if(tmp_num) { verbose=1; }

	unsigned int input_len_mask = 0xffffffff >> ((32-input_len));
	unsigned int hash_len_mask  = 0xffffffff >> ((4-hash_len)*8);

    printf("Hash input len   : %d\n", input_len);
    printf("Hash input lenmax: %d\n", input_len_max);
    printf("Hash result width: %d\n", hash_len);
    printf("Input mask   : %08x\n", input_len_mask);
    printf("Hash  mask   : %08x\n", hash_len_mask);
    printf("\n");


    /** *****************************************************************************************
     *  Start process
     */
    hashes *hobj = new hashes(input_len_mask, hash_len_mask);

	// create hash table
	int *hsrc_count = (int*)malloc((hash_len_mask+1) * sizeof(int));

	// reset hash tb
	int j;
	for(j=0; j<hash_len_mask; j++)
	{
		hsrc_count[j] = 0;
	}

	// make hash to sources count table
	printf("create hash to sources count table\n");
	time_t t = time(0);
    unsigned int i=0;
	for(i=0; i<input_len_mask; i++)
	{
		int h = hobj->hash(i);
		hsrc_count[h]++;

		if(time(0)-t > 1)
		{
			t=time(0);
			printf("%%%0.4f (%06x)\n", ((float)i/(float)input_len_mask*100), (unsigned int)i);	
		}
	}
	
	if(verbose)
	{
		printf("stat table:\n");
		int *hash_stats = (int*)malloc(hash_len_mask * sizeof(int));
		memcpy(hash_stats, hsrc_count, hash_len_mask * sizeof(int));

		// shell sort
		int h=(int)round((float)hash_len_mask/2);
		while(h>0)
		{
			int k;
			for(k=h; k<=hash_len_mask; k++)
			{
				int x = hash_stats[k];
				int jj = k;
				while(jj>=h && hash_stats[jj-h] > x)
				{
					hash_stats[jj] = hash_stats[jj-h];
					jj-=h;
				}
				hash_stats[jj] = x;
			}
			h=(int)round((float)h/2.2);
		}

		printf("h hits\tgroup_count\n");
		int last_count_value = -1;
		int group_count = 0;
		for(i=0; i<=hash_len_mask; i++)
		{
			if(hash_stats[i] != last_count_value)
			{
				if(last_count_value>=0)
				{
					printf("%d\t%d\n", last_count_value, group_count);
				}
				last_count_value = hash_stats[i];
				group_count=1;
			}
			else
			{
				group_count++;
			}
		}
		printf("%d\t%d\n", last_count_value, group_count);
		free(hash_stats);
	}

	//---
	// bits width
	int max_count = 0;
	int max_width = 0;
	int h;
	for(h=0; h<=hash_len_mask; h++)
	{
		if(max_count < hsrc_count[h])
		{
			max_count = hsrc_count[h];
		}

		if(max_width < bits_count(hsrc_count[h]))
		{
			max_width = bits_count(hsrc_count[h]);
		}
	}

	printf("Max variants width: %d\n", max_width);
	printf("Max variants count: %d\n", max_count);
	printf("Max In word     : %d\n", input_len);
	printf("Max archive word: %d\n", max_width + (hash_len*8));

	printf("\ncreate hash to sources table...");

	// make hash to src table
	int **hsrc = (int**)malloc((hash_len_mask+1) * sizeof(int*));

	// create and fill table with nulls
	for(h=0; h<=hash_len_mask; h++)
	{
		hsrc[h] = (int*)malloc((hsrc_count[h]+1) * sizeof(int)); // alloc hash table
		// clear hsrc[i][*]
		int j;
		for(j=0;j<hsrc_count[h];j++)
		{
			hsrc[h][j]=0;
		}
	}

	// fill hsrc with sources
	int filled = 0;
	for(i=0; i<input_len_mask; i++)
	{
		int h = hobj->hash(i);

		// find destination and fill it
		int j=0;
		for(j=0; j<hsrc_count[h]; j++)
		{
			if(!hsrc[h][j])
			{
				hsrc[h][j] = i;
				filled++;
				break;
			}
		}

		if(time(0)-t > 1)
		{
			t=time(0);
			printf("%%%0.4f (%06x)\n", ((float)i/(float)input_len_mask*100), (unsigned int)i);	
		}
	}
	printf("done.\n");
	printf("filled hsrc in %%%0.2f (%08x hits)\n\n", (float)((float)filled/(float)input_len_mask*100), filled);

	//init archive
	int srcLen = 1000;
	unsigned int *src1    = (unsigned int *)malloc(srcLen * sizeof(int)); // test data
	unsigned int *src2    = (unsigned int *)malloc(srcLen * sizeof(int)); // data after unarhive
	unsigned int *dst     = (unsigned int *)malloc(srcLen * sizeof(int));
	unsigned int *offsets = (unsigned int *)malloc(srcLen * sizeof(int)); // dst offsets
	int summaryBitsIn  = 0;
	int summaryBitsOut = 0;

	// fill test random data
	for(i=0; i<srcLen; i++)
	{
		src1[i] = (0xffff*rand() + rand()) & input_len_mask;
	}
	summaryBitsIn = bits_count(input_len_mask)*srcLen;
	printf("in bits length : %d\n", summaryBitsIn);

	int rightSectStat = 0; // count right section hits
	// archive
	for(i=0; i<srcLen; i++)
	{
		int h = hobj->hash( src1[i] ) & hash_len_mask;	
		dst[i] = h;

		// find src
		offsets[i]=0;
		for(j=0; j<hsrc_count[h]; j++)
		{
			if(hsrc[h][j] == src1[i])
			{
				offsets[i]=j;
				break;
			}
		}
		if(offsets[i] > (hsrc_count[h] / 2))
		{
			rightSectStat++;
		}

		summaryBitsOut += bits_count(hsrc_count[h]);
	}
	summaryBitsOut += bits_count(hash_len_mask)*srcLen;
	printf("out bits length: %d\n", summaryBitsOut);
	printf("\nright section offset stats: %%%0.2f (%d hits)\n", (float)((float)rightSectStat/(float)srcLen*100), rightSectStat);

	// unarchive

	// remove archiver vars
	free(offsets);
	free(dst);
	free(src1);
	free(src2);
	
	// remove hash table
	free(hsrc);
	free(hsrc_count);

	delete hobj;

	return 0;
}
