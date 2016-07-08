/*-
 * Copyright (c) 2015 Poul-Henning Kamp <phk@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * Reference implementation of code to retrieve current leap-second
 * announcement via DNS lookup.
 *
 * Specification:
 * --------------
 *
 * The leap second information is encoded into a IPv4 adress as follows:
 *
 *    3                   2                   1                   0
 *  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1|        month        | d |   dTAI      |    CRC-8      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 'month' Count of months since december 1971
 *  = (year - 1971) * 12 + month - 11
 *
 * 'dTAI'  Number of seconds UTC is behind of TAI
    UTC = TAI - dTAI
 *
 * 'd' what happens to dTAI at the end of the month indicated
 *  0 -> nothing
 *  1 -> subtract one from dTAI
 *  2 -> add one to dTAI
 *  3 -> Illegal
 *
 *
 * Example:
 * --------
 *
 * The IPv4 address "244.23.35.255" encodes Bulletin C 49
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1|0 1 0 0 0 0 0 1 0 1 1|1 0|0 1 0 0 0 1 1|1 1 1 1 1 1 1 1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * month = 0x20b = 523 = (2015 - 1971) * 12 + 6 - 11 -> June 2015
 *
 * d = 0x2 -> +1
 *
 * dTAI = 0x23 = 35 -> UTC = TAI - 35 sec
 *
 * CRC-8 = 0xff -> Calculated message {month d dTAI}.  See below.
 *
 * Design notes:
 * -------------
 *
 * The first four bits puts the resulting IPv4 address into the "class-E"
 * space which is "reserved for future use", as a defense against lying
 * DNS resolvers.
 *
 * At this point, late 2015, it does not look like class-E will ever be
 * allocated for any use.  Most network stacks treat them as martians
 * (ie: patently invalid), and at current consumption rates, they would
 * be gobbled up far faster than we could upgrade network stacks.
 *
 * Therefore no sane DNS resolver should ever return a class-E addres,
 * unless somebody does really strange things with IPv4 numbers.
 *
 * A second layer of defense against lying DNS resolvers is the CRC8
 * integrity check in the last octet.
 *
 * The field widths should be good until about year 2140.
 *
 * At this point in time the dTAI field is considered unsigned, but
 * should strange and awe inspiring geophysical events unfold,
 * spinning up the rotation of the planet, (while implausibly leaving
 * this protocol still relevant) the field can be redefined as signed.
 *
 *
 * Code notes:
 * -----------
 *
 * The reference implementation below has been written for maximum
 * portability an relies on text-processing rather than attempting
 * to pick struct sockaddr apart to decode the IPv4 number.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/*
 * MSB first CRC8 with polynomium (x^8 +x^5 +x^3 +x^2 +x +1)
 *
 * This is by a small margin the best CRC8 for the message length (28 bits)
 *
 * For much more about CRC's than you'd ever want to know:
 *
 *  http://users.ece.cmu.edu/~koopman/crc/index.html
 *
 * PS:  The CRC seed is not random.
 */

static int
crc8(uint32_t inp, int len)
{
	uint32_t crc = 0x54a9abf8 ^ (inp << (32 - len));
	int i;

	for (i = 0; i < len; i++) {
		if (crc & (1U << 31))
			crc ^= (0x12fU << 23);
		crc <<= 1;
	}
	return (crc >> 24);
}

/*
 * Decode a numeric IPv4 string ("253.253.100.11").
 *
 * 'year' and 'month' is the announced horizon.
 *
 * 'dtai' is what you subtract from TAI to get UTC until that month ends.
 *
 * 'delta' is what you do to dtai at the end of that month
 */

static int
decode_leapsecond(const char *ip, int *year, int *month, int *dtai, int *delta)
{
	int error;
	unsigned o1, o2, o3, o4;
	uint32_t u, d, mn, o;

	/* Zero returns in case of error ------------------------------*/

	if (year != NULL)
		*year = 0;
	if (month != NULL)
		*month = 0;
	if (dtai != NULL)
		*dtai = 0;
	if (delta != NULL)
		*delta = 0;

	/* Convert to 32 bit integer ----------------------------------*/

	error = sscanf(ip, "%u.%u.%u.%u", &o1, &o2, &o3, &o4);
	if (error != 4)
		return (-1);

	u = o1 << 24;
	u |= o2 << 16;
	u |= o3 << 8;
	u |= o4;

	/* Check & remove class E -------------------------------------*/

	if ((u >> 28) != 0xf)
		return (-1);

	u &= (1 << 28) - 1;

	/* Check & remove CRC8 ----------------------------------------*/

	if (crc8(u, 28) != 0x80)
		return (-2);

	u >>= 8;

	/* Split into fields ------------------------------------------*/

	o = u & 0x7f;
	u >>= 7;

	d = u & 3;
	u >>= 2;

	mn = (u & 0x7ff) + 10;

	/* Error checks -----------------------------------------------*/

	if (d == 3)
		return (-3);

	/* Convert to return values -----------------------------------*/

	if (year != NULL)
		*year = 1971 + (mn / 12);

	if (month != NULL)
		*month = 1 + (mn % 12);

	if (dtai != NULL)
		*dtai = o;

	if (delta != NULL) {
		switch (d) {
		case 0: *delta =  0; break;
		case 1: *delta = -1; break;
		case 2: *delta = +1; break;
		}
	}
	return (0);
}

/*
 * Query leapsecond.utcd.org for current leapsecond information
 */

static int
query_leapsecond(const char *fqdn,
    int *year, int *month, int *tai, int *delta, char **ip)
{
	struct addrinfo hints, *res, *res0;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(fqdn, NULL, &hints, &res0);
	if (error != 0) {
		fprintf(stderr, "Lookup error: %s\n", gai_strerror(error));
		return (-10);
	}
	error = -11;
	for (res = res0; res; res = res->ai_next) {
		error = getnameinfo(res->ai_addr,  res->ai_addrlen,
		    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (error != 0)
		continue;

		error = decode_leapsecond(hbuf, year, month, tai, delta);
		if (error == 0) {
			if (ip != NULL)
				*ip = strdup(hbuf);
			break;
		}
	}
	return (error);
}

static struct test_vector {
	const char *ip;
	int error;
	int year;
	int month;
	int tai;
	int delta;
} test_vectors[] = {
	{ "240.3.9.77",          0, 1971, 12,   9, +1 },
	{ "240.15.10.108",       0, 1972,  6,  10, +1 },
	{ "242.18.28.160",       0, 1993, 12,  28,  0 },
	{ "255.76.200.237",      0, 2135,  1,  72, -1 },
	{ "127.240.133.76",     -1,    0,  0,   0,  0 },
	{ "255.209.76.40",      -2,    0,  0,   0,  0 },
	{ "241.179.152.73",     -3,    0,  0,   0,  0 },
	{ NULL,                  0,    0,  0,   0,  0 }
};

int
main(int argc, char **argv)
{
	int error;
	int year, month, tai, delta;
	struct test_vector *tv;
	char *ip;

	(void)argc;
	(void)argv;

	printf("Checking test-vectors:\n\n");
	for (tv = test_vectors; tv->ip != NULL; tv++) {
		error = decode_leapsecond(tv->ip,
		    &year, &month, &tai, &delta);
		printf("  IP: %-15s  Error: %2d  Year: %4d  "
		    "Month %2d  dTAI: %3d  Delta: %2d\n",
		    tv->ip, error, year, month, tai, delta);
		assert(error == tv->error);
		assert(year == tv->year);
		assert(month == tv->month);
		assert(tai == tv->tai);
		assert(delta == tv->delta);
	}
	printf("\nIf you see this, the tests ran OK\n");

	printf("\n");
	printf("Querying currently published leapsecond announcement:\n\n");
	error = query_leapsecond("leapsecond.utcd.org",
	&year, &month, &tai, &delta, &ip);
	if (error) {
		printf("Failed with error %d\n", error);
		return (0);
	}

	printf("  IP: %-15s  Error: %2d  Year: %4d  "
	    "Month %2d  dTAI: %3d  Delta: %2d\n",
	    ip, error, year, month, tai, delta);

	printf("\nThat means:\n\n");
	printf("   Information is valid until end of UTC-month %d of year %d\n",
	    month, year);
	printf("   After that month: UTC = TAI - %d seconds\n", tai + delta);
	printf("   Until then:       UTC = TAI - %d seconds\n", tai);

	return (0);
}
