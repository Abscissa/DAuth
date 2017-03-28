module instauser.basic.util;

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

alias TokenBase64 = Base64Impl!('-', '_', '~'); /// Implementation of Base64 engine used for tokens.

/++
Compare two arrays in "length-constant" time. This thwarts timing-based
attacks by guaranteeing all comparisons (of a given length) take the same
amount of time.

See the section "Why does the hashing code on this page compare the hashes in
"length-constant" time?" at:
    $(LINK https://crackstation.net/hashing-security.htm)
+/
bool lengthConstantEquals(ubyte[] a, ubyte[] b)
{
	auto diff = a.length ^ b.length;
	for(int i = 0; i < a.length && i < b.length; i++)
		diff |= a[i] ^ b[i];

	return diff == 0;
}
