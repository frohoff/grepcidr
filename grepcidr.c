/*

  grepcidr 2.0 - Filter IPv4 and IPv6 addresses matching CIDR patterns
  Copyright (C) 2004 - 2014  Jem E. Berkes <jem@berkes.ca>
  www.berkes.ca

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define EXIT_OK		0
#define EXIT_NOMATCH	1
#define EXIT_ERROR	2

#define TXT_VERSION	"grepcidr 2.0\nCopyright (C) 2004 - 2014  Jem E. Berkes <jem@berkes.ca>\n"
#define TXT_USAGE	"Usage:\n" \
			"\tgrepcidr [-V] [-cisvx] PATTERN [FILE...]\n" \
			"\tgrepcidr [-V] [-cisvx] [-e PATTERN | -f PATFILE] [FILE...]\n"
#define TXT_USAGE2	"grepcidr: Specify PATTERN or -f FILE to read patterns from\n"
#define TXT_BADPAT	"grepcidr: Not a valid pattern"
#define TXT_FATAL	"grepcidr: Fatal error: unexpected size of data type(s) on this system!\n"
#define TXT_MEMORY	"grepcidr: Fatal error: out of memory!\n"

/* Use GREPERROR instead of perror */
#define GREPERROR(prefix) fprintf(stderr, "grepcidr: %s: %s\n", prefix, strerror(errno));

#define MAXFIELD	512
#define TOKEN_SEPS	" \t,\r\n"	/* so user can specify multiple patterns on command line */
#define INIT_NETWORKS	8192

/*
	Specifies a network. Whether originally in CIDR format (IP/mask)
	or a range of IPs (IP_start-IP_end), spec is converted to a range.
	The range is min to max (32-bit IPs) inclusive.
*/
struct netspec
{
	unsigned int min;
	unsigned int max;
};

/* IPv6 version of pattern */
struct netspec6
{
	unsigned char min[16];
	unsigned char max[16];
};


/* Macro to test for valid IP address in four integers */
#define VALID_IP(IP) ((IP[0]<256) && (IP[1]<256) && (IP[2]<256) && (IP[3]<256))
/* Macro to build 32-bit IP from four integers */
#define BUILD_IP(IP) ((IP[0]<<24) | (IP[1]<<16) | (IP[2]<<8) | IP[3])

/* Parameters and macros for hints-based search */
#define HINT_LOOKAHEAD	4	/* e.g. if hints looks at P[4], then use 4 */

#define IPV4_FIELD		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz."
#define IPV4_BUFSIZE	16
#define IPV4_HINT(P)	(isdigit((int)P[0]) && ((P[1]=='.') || (P[2]=='.') || (P[3]=='.')))

#define IPV6_FIELD		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:."
#define IPV6_BUFSIZE	46
#define IPV6_HINT1(P)	((P[0]==':') && (P[1]==':') && isxdigit((int)P[2]))
#define IPV6_HINT2(P)	(isxdigit((int)P[0]) && (P[1]==':'))
#define IPV6_HINT3(P)	(isxdigit((int)P[0]) && isxdigit((int)P[1]) && (P[2]==':'))
#define IPV6_HINT4(P)	(isxdigit((int)P[0]) && isxdigit((int)P[1]) && isxdigit((int)P[2]) && (P[3]==':'))
#define IPV6_HINT5(P)	(isxdigit((int)P[0]) && isxdigit((int)P[1]) && isxdigit((int)P[2]) && isxdigit((int)P[3]) && (P[4]==':'))


/* Global variables */
int anymatch = 0;				/* did anything match? for exit code */
int invert = 0;				/* flag for inverted mode */
unsigned int counting = 0;		/* when non-zero, counts matches */
int include_noip = 0;			/* flag to include lines without IPs when inverting */
int strict_align = 0;			/* flag to enforce strict base alignment */
int strict_nosearch = 0;			/* flag for original style, single IP match */
int match_one = 0;				/* for -v, have matched one IP on this line */
int seen_ip = 0;				/* for -v, have seen an IP on this line */
int shownames = 0;				/* show file names with output lines */

unsigned int patterns = 0;		/* total patterns in IPv4 array */
unsigned int capacity = 0;		/* current capacity of IPv4 array */
struct netspec* array = NULL;		/* IPv4 array of patterns */

unsigned int patterns6 = 0;		/* total patterns in IPv6 array */
unsigned int capacity6 = 0;		/* current capacity of IPv6 array */
struct netspec6* array6 = NULL;	/* IPv6 array of patterns */

/*
	Insert new spec inside array of network spec
	Dynamically grow array buffer as needed
	The array must have already been initially allocated, with valid capacity
*/
void array_insert(struct netspec* newspec)
{
	if (patterns == capacity)
	{
		capacity *= 2;
		array = realloc(array, capacity*sizeof(struct netspec));
	}
	array[patterns++] = *newspec;
}

void array_insert6(struct netspec6* newspec)
{
	if (patterns6 == capacity6)
	{
		capacity6 *= 2;
		array6 = realloc(array6, capacity6*sizeof(struct netspec6));
	}
	array6[patterns6++] = *newspec;
}


/*
	Convert IPv4 address string at location p, string length len,
	into result which must point to an unsigned int.
	Returns 1 on success, 0 on failure
*/
int ipv4_to_uint(const char* p, unsigned long len, unsigned int* result)
{
	unsigned char parsed[4] = { 0 };
	char buf[IPV4_BUFSIZE];
	if (len > IPV4_BUFSIZE-1) return 0;	/* too long to be a valid IPv4 */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, p, len);
	if (inet_pton(AF_INET, buf, &parsed) == 1)
	{
		*result = BUILD_IP(parsed);
		return 1;
	}
	else
		return 0;
}


/*
	Convert IPv6 address string at location p, string length len,
	into result which must point to 16 byte unsigned char array.
	This uses system's inet_pton() which is quite fast on Linux.
	Returns 1 on success, 0 on failure
*/
int ipv6_to_uchar(const char* p, unsigned long len, unsigned char* result)
{
	char buf[IPV6_BUFSIZE];
	if (len > IPV6_BUFSIZE-1) return 0;	/* too long to be a valid IPv6 */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, p, len);
	if (inet_pton(AF_INET6, buf, result) == 1)
		return 1;
	else
		return 0;
}


/*
	Increment IPv6 address (array at input) and store result.
	Both input and result must point to 16 byte unsigned char array.
*/
void ipv6_increment(unsigned char* input, unsigned char* result)
{
	int i, carry=1;
	for (i=15; i>=0; i--)	/* network byte order is big endian */
	{
		int sum = input[i] + carry;
		result[i] = (unsigned char)(sum & 0xFF);
		carry = sum >> 8;
	}
}


/*
	Given string, fills in the struct netspec (must be allocated)
	Accept CIDR IP/mask format or IP_start-IP_end range.
	Returns true (nonzero) on success, false (zero) on failure.
*/
int net_parse(const char* line, struct netspec* spec)
{
	unsigned int IP1[4], IP2[4];
	int maskbits = 32;	/* if using CIDR IP/mask format */
	
	/* Try parsing IP/mask, CIDR format */
	if (strchr(line, '/') && (sscanf(line, "%u.%u.%u.%u/%d", &IP1[0], &IP1[1], &IP1[2], &IP1[3], &maskbits) == 5)
		&& VALID_IP(IP1))
	{
		unsigned int ipaddress = BUILD_IP(IP1);
		if (maskbits == 0)
		{
			if (strict_align && (ipaddress != 0))
				return 0;	/* invalid */
			spec->min = 0;
			spec->max = 0xFFFFFFFF;
			return 1;
		}
		else if ((maskbits < 0) || (maskbits > 32))
			return 0;	/* invalid */
		if (strict_align && (ipaddress & (((1 << (32-maskbits))-1) & 0xFFFFFFFF)))
			return 0;	/* invalid, there are non-zero host bits */
		spec->min = ipaddress & (~((1 << (32-maskbits))-1) & 0xFFFFFFFF);
		spec->max = spec->min | (((1 << (32-maskbits))-1) & 0xFFFFFFFF);
		return 1;
	}
	/* Try parsing a range. Spaces around hyphen are optional. */
	else if (strchr(line, '-') && (sscanf(line, "%u.%u.%u.%u - %u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3],
		&IP2[0], &IP2[1], &IP2[2], &IP2[3]) == 8) && VALID_IP(IP1) && VALID_IP(IP2))
	{
		spec->min = BUILD_IP(IP1);
		spec->max = BUILD_IP(IP2);
		if (spec->max >= spec->min)
			return 1;
		else
			return 0;
	}
	/* Try simple IP address */
	else if ((sscanf(line, "%u.%u.%u.%u", &IP1[0], &IP1[1], &IP1[2], &IP1[3]) == 4) && VALID_IP(IP1))
	{
		spec->min = BUILD_IP(IP1);
		spec->max = spec->min;
		return 1;
	}
	return 0;	/* could not parse */
}


/*
	Parse an IPv6 pattern (struct netspec6)
	Accepts IP or IP/x format
	Returns true (nonzero) on success, false (zero) on failure.
*/
int net_parse6(const char* line, struct netspec6* v6spec)
{
	size_t field_len = strspn(line, IPV6_FIELD);
	unsigned char address[16] = { 0 };
	int maskbits = 128;

	if (!ipv6_to_uchar(line, field_len, address))
		return 0;	/* no IPv6 found here */
	/* Simple IPv6 address is in address */
	memcpy(v6spec->min, address, 16);
	memcpy(v6spec->max, address, 16);
	if (sscanf(line+field_len, "/%d", &maskbits) == 1)
	{
		unsigned char mask;
		int bytenum;
		if ((maskbits < 0) || (maskbits > 128))
			return 0;	/* invalid */
		if (maskbits == 0)
			bytenum = -1;
		else
		{
			bytenum = (maskbits-1)/8;
			mask = (unsigned char)0xFF << (7 - ((maskbits-1)%8));
			v6spec->min[bytenum] &= mask;
			v6spec->max[bytenum] |= (unsigned char)~mask;
		}
		for (++bytenum; bytenum<16; bytenum++)
		{
			v6spec->min[bytenum] = 0;
			v6spec->max[bytenum] = 0xFF;
		}
		if (strict_align && (memcmp(v6spec->min, address, 16) != 0))
			return 0;	/* bad CIDR alignment */
	}
	return 1;
}


/* Compare two netspecs, for sorting. Comparison is done on minimum of range */
int netsort(const void* a, const void* b)
{
	unsigned int c1 = ((struct netspec*)a)->min;
	unsigned int c2 = ((struct netspec*)b)->min;
	if (c1 < c2) return -1;
	if (c1 > c2) return +1;
	return 0;
}


int netsort6(const void* a, const void* b)
{
	unsigned char* c1 = ((struct netspec6*)a)->min;
	unsigned char* c2 = ((struct netspec6*)b)->min;
	int n = memcmp(c1, c2, 16);
	if (n < 0) return -1;
	if (n > 0) return +1;
	return 0;
}


/* Compare two netspecs, for searching. Test if key (only min) is inside range */
int netsearch(const void* a, const void* b)
{
	unsigned int key = ((struct netspec*)a)->min;
	unsigned int min = ((struct netspec*)b)->min;
	unsigned int max = ((struct netspec*)b)->max;
	if (key < min) return -1;
	if (key > max) return +1;
	return 0;
}


int netsearch6(const void* a, const void* b)
{
	unsigned char* key = ((struct netspec6*)a)->min;
	unsigned char* min = ((struct netspec6*)b)->min;
	unsigned char* max = ((struct netspec6*)b)->max;
	if (memcmp(key, min, 16) < 0) return -1;
	if (memcmp(key, max, 16) > 0) return +1;
	return 0;
}


/* Action to take upon a matching line, print the line or count it */
void print_or_count(char* line, const char* filename)
{
	anymatch = 1;
	if (counting)
		counting++;
	else
	{
		if (filename && shownames)
			printf("%s:", filename);
		printf("%s", line);
	}
}


/*
	Search for this IP (passed in key) among loaded network patterns and determine if it's a "match"
	Provide either an IPv4 or IPv6 key, but not both.  Returns true or false, whether IP matched patterns.
*/
int match_ip(struct netspec* v4key, struct netspec6* v6key, char* line, const char* filename)
{
	int match = 0;
	seen_ip = 1;
	if (v4key && bsearch(v4key, array, patterns, sizeof(struct netspec), netsearch))
		match = 1;
	else if (v6key && bsearch(v6key, array6, patterns6, sizeof(struct netspec6), netsearch6))
		match = 1;
	if (match)
	{
		match_one = 1;
		if (!invert) print_or_count(line, filename);	/* take action if not using -v */
	}
	return match;
}


/* Load patterns defining networks */
void load_patterns(const char* pat_filename, char* pat_strings)
{
	if (pat_filename)
	{
		FILE* data = fopen(pat_filename, "r");
		if (data)
		{
			char line[MAXFIELD];
			while (fgets(line, sizeof(line), data))
			{
				struct netspec ipv4_pat;
				struct netspec6 ipv6_pat;
				if ((*line=='#')||(*line=='\n')||(*line=='\r'))
					continue;	/* skip blank lines and comments */
				if (net_parse(line, &ipv4_pat))
					array_insert(&ipv4_pat);
				else if (net_parse6(line, &ipv6_pat))
					array_insert6(&ipv6_pat);
				else
					fprintf(stderr, TXT_BADPAT ": %s", line);
			}
			fclose(data);
		}
		else
		{
			GREPERROR(pat_filename);
			exit(EXIT_ERROR);
		}
	}
	if (pat_strings)
	{
		char* token = strtok(pat_strings, TOKEN_SEPS);
		while (token)
		{
			struct netspec ipv4_pat;
			struct netspec6 ipv6_pat;
			if (net_parse(token, &ipv4_pat))
				array_insert(&ipv4_pat);
			else if (net_parse6(token, &ipv6_pat))
				array_insert6(&ipv6_pat);
			else
				fprintf(stderr, TXT_BADPAT ": %s\n", token);
			token = strtok(NULL, TOKEN_SEPS);
		}
	}

	/* Prepare array for rapid searching */
	if (patterns)
	{
		unsigned int item;
		qsort(array, patterns, sizeof(struct netspec), netsort);
		/* cure overlaps so that ranges are disjoint and consistent */
		for (item=1; item<patterns; item++)
		{
			if (array[item].max <= array[item-1].max)
				array[item] = array[item-1];
			else if (array[item].min <= array[item-1].max)
				array[item].min = array[item-1].max + 1;	/* overflow possibility */
		}
	}
	if (patterns6)
	{
		unsigned int item;
		qsort(array6, patterns6, sizeof(struct netspec6), netsort6);
		/* cure overlaps so that ranges are disjoint and consistent */
		for (item=1; item<patterns6; item++)
		{
			if (memcmp(array6[item].max, array6[item-1].max, 16) <= 0)
				array6[item] = array6[item-1];
			else if (memcmp(array6[item].min, array6[item-1].max, 16) <= 0)
				ipv6_increment(array6[item-1].max, array6[item].min);
		}
	}
}


/*
	Scan the buffer (one line) for IPv4 and IPv6 addresses.
	While moving through buffer, look for 'hints' that a valid address may
	exist at this location before trying parser.  This is much faster than regex.
	We check p[0] so that we stop at terminating nul char.
*/
void scan_with_hints(char* buffer, unsigned long bufsize, const char* filename)
{
	char* p;
	char* max = buffer + bufsize - 1 - HINT_LOOKAHEAD;
	if (bufsize <= HINT_LOOKAHEAD)
		return;
	for (p = buffer; (p < max) && p[0]; p++)
	{
		/* Search for IPv4 */
		if (patterns && IPV4_HINT(p))
		{
			size_t field_len = strspn(p, IPV4_FIELD);
			struct netspec v4key;
			if (ipv4_to_uint(p, field_len, &v4key.min))
			{
				if (match_ip(&v4key, NULL, buffer, filename))
					return;	/* found match, stop scanning inside line */
			}
			p += field_len - 1;
			continue;
		}
		/* Search for IPv6 */
		if (patterns6)
		{
			if (IPV6_HINT1(p)||IPV6_HINT2(p)||IPV6_HINT3(p)||IPV6_HINT4(p)||IPV6_HINT5(p))
			{
				size_t field_len = strspn(p, IPV6_FIELD);
				struct netspec6 v6key;
				if (ipv6_to_uchar(p, field_len, v6key.min))
				{
					if (match_ip(NULL, &v6key, buffer, filename))
						return;	/* found match, stop scanning inside line */
				}
				p += field_len - 1;
				continue;
			}
		}
	}
}


/*
	Somewhat like GNU getline(), returns an arbitrarily long whole line in *bufptr
	Returns 0 when end of stream occurs and no characters are read, or 1 if a line is read.
	Buffer remains allocated in multiple calls, but caller should free *bufptr when done.
*/
int fgets_whole_line(char **bufptr, size_t *bufsize, FILE* stream)
{
	size_t bufcur = 0;
	if (*bufptr == NULL)
	{
		*bufptr = malloc(MAXFIELD);
		*bufsize = MAXFIELD;
		if (*bufptr == NULL)
		{
			fprintf(stderr, TXT_MEMORY);
			exit(EXIT_ERROR);
		}
	}
	while (fgets((*bufptr)+bufcur, (*bufsize)-bufcur, stream))
	{
		size_t len = bufcur + strlen(*bufptr + bufcur);
		if (len < 1) return 1;
		if ((bufptr[0][len-1] == '\n') || feof(stream))
			return 1;
		*bufsize *= 2;
		*bufptr = realloc(*bufptr, *bufsize);
		if (*bufptr == NULL)
		{
			fprintf(stderr, TXT_MEMORY);
			exit(EXIT_ERROR);
		}
		bufcur = len;
	}
	return 0;
}


/* Match IPs from input stream to network patterns */
void search_stream(FILE* input_stream, const char* filename)
{
	char* line = NULL;
	size_t linesize = 0;
	while (fgets_whole_line(&line, &linesize, input_stream))
	{
		match_one = 0;
		seen_ip = include_noip;
		if (strict_nosearch)
		{
			/* Faster old-style search, look for single IP from start of line */
			int ipv4_match = 0;
			if (patterns)
			{
				size_t field_len = strspn(line, IPV4_FIELD);
				struct netspec v4key;
				if (ipv4_to_uint(line, field_len, &v4key.min))
					ipv4_match = match_ip(&v4key, NULL, line, filename);
			}
			if (!ipv4_match && patterns6)
			{
				size_t field_len = strspn(line, IPV6_FIELD);
				struct netspec6 v6key;
				if (ipv6_to_uchar(line, field_len, v6key.min))
					match_ip(NULL, &v6key, line, filename);
			}
		}
		else
			scan_with_hints(line, linesize, filename);	/* scan whole line */
		
		/* If using -i or -v, take action once the whole line has been processed */
		if (invert && seen_ip && !match_one)
			print_or_count(line, filename);
	}
	free(line);
}



int main(int argc, char* argv[])
{
	static char shortopts[] = "ce:f:isvxV";
	char* pat_filename = NULL;		/* filename containing patterns */
	char* pat_strings = NULL;		/* pattern strings on command line */
	int foundopt;
	
	if ((CHAR_BIT != 8) || (sizeof(unsigned int) < 4) ||
		(sizeof(struct in_addr) != 4) || (sizeof(struct in6_addr) != 16))
	{
		fprintf(stderr, TXT_FATAL);
		return EXIT_ERROR;
	}

	if (argc == 1)
	{
		fprintf(stderr, TXT_USAGE);
		return EXIT_ERROR;
	}

	while ((foundopt = getopt(argc, argv, shortopts)) != -1)
	{
		switch (foundopt)
		{
			case 'V':
				puts(TXT_VERSION);
				return EXIT_ERROR;
				
			case 'c':
				counting = 1;
				break;
				
			case 's':
				strict_align = 1;
				break;
				
			case 'i':
				include_noip = 1;
			case 'v':
				invert = 1;
				break;
				
			case 'x':
				strict_nosearch = 1;
				break;
				
			case 'e':
				pat_strings = optarg;
				break;

			case 'f':
				pat_filename = optarg;
				break;
				
			default:
				fprintf(stderr, TXT_USAGE);
				return EXIT_ERROR;
		}
	}
	
	if (!pat_filename && !pat_strings)
	{
		if (optind < argc)
			pat_strings = argv[optind++];
		else
		{
			fprintf(stderr, TXT_USAGE2);
			return EXIT_ERROR;
		}
	}

	/* Initial array allocation */
	capacity = INIT_NETWORKS;
	array = (struct netspec*) malloc(capacity*sizeof(struct netspec));
	capacity6 = INIT_NETWORKS;
	array6 = (struct netspec6*) malloc(capacity6*sizeof(struct netspec6));
	if (!array || !array6)
	{
		fprintf(stderr, TXT_MEMORY);
		return EXIT_ERROR;
	}

	load_patterns(pat_filename, pat_strings);
	do
	{	/* Search each specified file name, or just stdin */
		const char* curfilename = NULL;
		FILE* inp_stream;
		if (optind >= argc)
			inp_stream = stdin;
		else
		{
			/* One or more file names are specified on the command line */
			if (optind+1 < argc) shownames = 1;	/* more than one file */
			curfilename = argv[optind++];
			inp_stream = fopen(curfilename, "r");
			if (!inp_stream)
			{
				GREPERROR(curfilename);
				return EXIT_ERROR;
			}
		}
		/* Ready to search this stream or file */
		search_stream(inp_stream, curfilename);
		if (inp_stream != stdin)
			fclose(inp_stream);
	} while (optind < argc);
	
	if (counting)
		printf("%u\n", counting-1);
	/* Cleanup */
	if (array)
		free(array);
	if (array6)
		free(array6);
	if (anymatch)
		return EXIT_OK;
	else
		return EXIT_NOMATCH;
}
