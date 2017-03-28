module instauser.basic.salt;

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

alias Salt = ubyte[]; /// Salt type
alias Salter(TDigest) = void delegate(ref TDigest, Password, Salt); /// Convenience alias for salter delegates.

/// Default salter for 'makeHash' and 'isSameHash'.
void defaultSalter(TDigest)(ref TDigest digest, Password password, Salt salt)
	if(isAnyDigest!TDigest)
{
	digest.put(cast(immutable(ubyte)[])salt);
	digest.put(password.data);
}
