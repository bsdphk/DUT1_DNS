#!/usr/local/bin/python

from __future__ import print_function

import random

def crc8(b, n):
	poly = 0x12f << 23
	assert poly & (1 << 31)

	# I chose 0xcf after an exhaustive search for best performance
	# on 28 bit messages.
	#
 	# bit-     Missed     Total   Miss-Rate
	# errors
	# -------------------------------------
	#  <=1          0        28    0.000000
	#  <=2          0       406    0.000000
	#  <=3          0      3682    0.000000
	#  <=4         81     24157    0.003353
	#  <=5        532    122437    0.004345
	#  <=6       1972    499177    0.003951
	#  <=7       6494   1683217    0.003858
	#  <=8      18736   4791322    0.003910
	# -------------------------------------

	assert b >= 0
	crc = 0x54a9abf8 ^ (b << (32 - n))
	assert crc >= 0
	for i in range(n):
		if crc & (1 << 31):
			crc ^= poly
		assert not crc & (1 << 31)
		assert crc >= 0
		crc <<= 1
	crc >>= 24
	return crc

def dec(i):
	r = ""
	j = i.split(".")
	assert len(j) == 4
	for k in range(4):
		j[k] = int(j[k])
	w = j[0] << 24
	w |= j[1] << 16
	w |= j[2] << 8
	w |= j[3]

	assert (w >> 28) == 0xf
	w &= (1 << 28) - 1

	if crc8(w, 28) == 0x80:
		r += "OK "
	else:
		r += "BAD %02x" % crc8(w, 28)

	w >>= 8

	b = w & 0x7f
	w >>= 7	
	d = w & 0x03
	w >>= 2	
	mn = w

	mn += 10
	m = (mn % 12) + 1
	y = mn / 12 + 1971
	# assert d != 3
	if d == 2:
		dt = +1
	elif d == 3:
		dt = +2
	elif d == 1:
		dt = -1
	else:
		dt = 0
	r += " %04d" % y
	r += " %2d" % m
	r += " %+4d" % b
	r += " %+2d" % dt
	return r

def enc(y, m, b, a):

	# Encode the month number.  Dec 1971 = 0
	w = (y - 1971) * 12 + m - 11
	assert w < 2048

	# Encode the leap-second polarity
	# XXX: It is possible to steal a bit here if negative leapseconds
	# XXX: can be definitively ruled out.
	w <<= 2
	if a == b + 1:
		w |= 0x2
	elif a == b - 1:
		w |= 0x1

	# Encode present UTC-TAI difference
	w <<= 7
	w |= b

	# Add CRC8
	c = crc8(w, 20)
	w <<= 8
	w |= c

	assert not w & ~((1<<28) - 1)

	assert 0x80 == crc8(w, 28)

	w |= 0xf << 28

	# Split in bytes and append CRC
	z = [w >> 24, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff]

	i = "%d.%d.%d.%d" % (z[0], z[1], z[2], z[3])
	print("%4d %2d %6d %6d %08x  %02x %-15s -> %s" %
	    (y, m, b, a, w, z[3], i, dec(i)))


print("YYYY MM before  after  encoded crc IP               Decoded")
print("-" * 73)

ll = list()
lmnum = 6
ldut1 = 9
fi = open("_Cache_Leap_Second_History.dat")
for l in fi:
	i = l.split()
	if len(i) == 0 or i[0][0] == "#":
		continue
	assert i[1] == "1"
	month = int(i[2])
	assert month >= 1 and month <= 12
	year = int(i[3])
	assert year >= 1972
	if month == 1:
		month = 12
		year -= 1
	elif month == 7:
		month -= 1
	dut1 = int(i[4])
	mnum = (year - 1972) * 12 + month - 1
	for x in range(lmnum, mnum, 6):
		y = 1972 + (x+1) // 12
		m = (x+1) % 12
		enc(y, m, ldut1, ldut1)
	enc(year, month, ldut1, dut1)
	lmnum = mnum + 6
	ldut1 = dut1
print("")

enc(2016, 12, 36, 37)

exit(0)

for year in range(2016, 2145):
	for month in (1, 7):
		if random.randint(0, 2) == 0:
			dut1 += 1
		enc(year, month, ldut1, dut1)
		ldut1 = dut1
print("-" * 73)
