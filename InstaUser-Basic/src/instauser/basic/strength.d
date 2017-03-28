module instauser.basic.strength;

import std.algorithm;
import std.array;
import ascii = std.ascii;
import std.base64;
import std.conv;
import std.digest.crc;
import std.digest.md;
import std.digest.ripemd;
import std.digest.sha;
import std.exception;
import std.functional;
import std.random;
import std.range;
import std.traits;
import std.typecons;

import instauser.basic.random : randomSalt;
import instauser.basic.hashdrbg;

import instauser.basic.digest;
import instauser.basic.exceptions;
import instauser.basic.hash;
import instauser.basic.password;
import instauser.basic.random;
import instauser.basic.salt;
import instauser.basic.tests;
import instauser.basic.util;

version(InstaUser_AllowWeakSecurity) {} else
{
	version = DisallowWeakSecurity;
}

/++
Note, this only checks Phobos's RNG's and digests, and only by type. This
works on a blacklist basis - it blindly accepts any Phobos-compatible RNG
or digest it does not know about. This is only supplied as a convenience. It
is always your own responsibility to select an appropriate algorithm for your
own needs.

And yes, unfortunately, this does currently rule out all RNG's and most
digests currently in Phobos. They are all known to be fairly weak
for password-hashing purposes, even SHA1 which despite being heavily used
has known security flaws.

For random number generators, you should use a CPRNG (cryptographically secure
pseudorandom number generator):
    $(LINK http://en.wikipedia.org/wiki/Cryptographically_secure_pseudo-random_number_generator )

For digests, you should use one of the SHA-2 algorithms (for example, SHA512)
or, better yet, an established "key stretching" algorithm
( $(LINK http://en.wikipedia.org/wiki/Key_stretching#History) ), intended
for password hashing. These contain deliberate inefficiencies that cannot be
optimized away even with massive parallelization (such as a GPU cluster). These
are NOT too inefficient to use for even high-traffic authentication, but they
do thwart the parallelized brute force attacks that algorithms used for
streaming data encryption, such as SHA, are increasingly susceptible to.
    $(LINK https://crackstation.net/hashing-security.htm)
+/
bool isKnownWeak(T)() if(isDigest!T || isInstaUserRandom!T)
{
	return
		is(T == CRC32) ||
		is(T == MD5) ||
		is(T == RIPEMD160) ||
		is(T == SHA1) ||
		isInstanceOf!(LinearCongruentialEngine, T) ||
		isInstanceOf!(MersenneTwisterEngine, T) ||
		isInstanceOf!(XorshiftEngine, T);
}

///ditto
bool isKnownWeak(T)(T digest) if(is(T : Digest))
{
	return
		cast(CRC32Digest)digest ||
		cast(MD5Digest)digest ||
		cast(RIPEMD160Digest)digest ||
		cast(SHA1Digest)digest;
}

version(InstaUserBasic_Unittest)
unittest
{
	assert(isKnownWeak!MinstdRand0);
	assert(isKnownWeak!Mt19937);
	assert(isKnownWeak!Xorshift128);
	assert(isKnownWeak!MD5);
	assert(!isKnownWeak!(HashDRBG!uint));
	assert(!isKnownWeak!(HashDRBGStream!()));
}

void validateStrength(T)() if(isDigest!T || isInstaUserRandom!T)
{
	version(DisallowWeakSecurity)
	{
		static if(isKnownWeak!T())
		{
			pragma(msg, "ERROR: "~T.stringof~" - "~KnownWeakException.message);
			static assert(false);
		}
	}
}

void validateStrength(Digest digest)
{
	version(DisallowWeakSecurity)
	{
		enforce(!isKnownWeak(digest),
			new KnownWeakException(defaultDigestCodeOfObj(digest)));
	}
}
