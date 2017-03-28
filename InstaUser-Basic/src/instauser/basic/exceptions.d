module instauser.basic.exceptions;

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
import instauser.basic.salt;
import instauser.basic.strength;
import instauser.basic.tests;
import instauser.basic.util;

/++
Thrown whenever a digest type cannot be determined.
For example, when the provided (or default) 'digestCodeOfObj' or 'digestFromCode'
delegates fail to find a match. Or when passing isSameHash a
Hash!Digest with a null 'digest' member (which prevents it from determining
the correct digest to match with).
+/
class UnknownDigestException : Exception
{
	this(string msg) { super(msg); }
}

/++
Thrown when a known-weak algortihm or setting it attempted, UNLESS
compiled with '-version=InstaUser_AllowWeakSecurity'
+/
class KnownWeakException : Exception
{
	static enum message =
		"This is known to be weak for salted password hashing. "~
		"If you understand and accept the risks, you can force InstaUser "~
		"to allow it with -version=InstaUser_AllowWeakSecurity";
	
	this(string algoName)
	{
		super(algoName ~ " - " ~ message);
	}
}
