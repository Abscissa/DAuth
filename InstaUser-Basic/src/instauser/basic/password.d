module instauser.basic.password;

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
A reference-counted type for passwords. The memory containing the password
is automatically zeroed-out when there are no more references or when
a new password is assigned.

If you keep any direct references to Password.data, be aware it may get cleared.

Create a Password via functions 'toPassword' or 'dupPassword'.

The payload is a private struct that supports the following:

---------------------------------------------------------
	@property ubyte[] data(): Retrieve the actual plaintext password

	@property size_t length() const: Retrieve the password length

	void opAssign(PasswordData rhs): Assignment

	void opAssign(ubyte[] rhs): Assignment

	~this(): Destructor
---------------------------------------------------------
+/
alias Password = RefCounted!PasswordData;

/// Payload of Password
private struct PasswordData
{
	private ubyte[] _data;
	
	@property ubyte[] data()
	{
		return _data;
	}
	
	@property size_t length() const
	{
		return _data.length;
	}
	
	void opAssign(PasswordData rhs)
	{
		opAssign(rhs._data);
	}
	
	void opAssign(ubyte[] rhs)
	{
		clear();
		this._data = rhs;
	}
	
	~this()
	{
		clear();
	}

	private void clear()
	{
		_data[] = 0;
	}
}

/++
Constructs a Password from a ubyte[].
Mainly provided for syntactic consistency with 'toPassword(char[])'.
+/
Password toPassword(ubyte[] password)
{
	return Password(password);
}

/++
Constructs a Password from a char[] so you don't have to cast to ubyte[],
and don't accidentally cast away immutability.
+/
Password toPassword(char[] password)
{
	return Password(cast(ubyte[])password);
}

/++
This function exists as a convenience in case you need it, HOWEVER it's
recommended to design your code so you DON'T need to use this (use
toPassword instead):

Using this to create a Password cannot protect the in-memory data of your
original string because a string's data is immutable (this function must
.dup the memory).

While immutability usually improves safety, you should avoid ever storing
unhashed passwords in immutables because they cannot be reliably
zero-ed out.
+/
Password dupPassword(string password)
{
	return toPassword(password.dup);
}
