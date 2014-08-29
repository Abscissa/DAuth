DAuth - Authentication Utility for D
====================================

[[ChangeLog](https://github.com/Abscissa/DAuth/blob/master/CHANGELOG.md)] [[API Reference](http://semitwist.com/dauth/)]

DAuth (soon to be rebranded as "InstaUser Basic") is a [salted password hash](http://en.wikipedia.org/wiki/Salt_%28cryptography%29) authentication library for [D](http://dlang.org). It provides a simple, yet flexible API. With it, your software can easily incorporate user accounts with reliable, upgradable security.

You can have as much or as little control as you need. This makes DAuth suitable for both new projects and interfacing with any existing hashed-password store.

By default, DAuth uses known-good hashing and randomization algorithms (currently SHA-512 and Hash_DRBG), but it accepts any [Phobos](http://dlang.org/phobos/)-compatible [hash digest](http://dlang.org/phobos/std_digest_digest.html) or [random number generator](http://dlang.org/phobos/std_random.html).

DAuth's main interface is makeHash and isSameHash:

- ```makeHash(Password)```: Generates a salted hash for a password.

- ```isSameHash(Password, Hash)```: Validates a password against an existing hash. The hashes are compared using a ["length-constant" time](https://crackstation.net/hashing-security.htm) algorithm to thwart timing-based attacks.

```d
import dauth;
//...
char[] input = ...;
Password pass = toPassword(input); // Ref counted with automatic memory zeroing

// makeHash: Salt is crypto-secure randomized
string hash1 = makeHash(pass).toString(); // Ex: [SHA512]d93Tp...ULle$my7MSJu...NDtd5RG
string hash2 = makeHash(pass).toCryptString(); // Ex: $6$d93Tp...ULle$my7MSJu...NDtd5RG

// isSameHash: Compared using "length-constant" time
bool ok1 = isSameHash(pass, parseHash("[SHA512]d93Tp...ULle$my7MSJu...NDtd5RG"));
bool ok2 = isSameHash(pass, parseHash("$6$d93Tp...ULle$my7MSJu...NDtd5RG"));
```

The library provides a forward-compatible string-based hash format for easy storage and retrieval using any hash digest type. It also has native support for Unix [crypt(3)](https://en.wikipedia.org/wiki/Crypt_%28C%29)-style hash strings for MD5, SHA-256 and SHA-512.

Additionally, there is a [```dauth.random```](http://semitwist.com/dauth/random.html) module with functions for randomly generating [salts](http://semitwist.com/dauth/random.html#randomSalt), [passwords](http://semitwist.com/dauth/random.html#randomPassword) and [single-use tokens](http://semitwist.com/dauth/random.html#randomToken):

```d
// All parameters are optional: Desired length, random number generator,
// token strength, and chars permitted in the password:

Password pass = randomPassword();
ubyte[]  salt = randomSalt();
string   singleUse = randomToken();

Password pass2 = randomPassword!DefaultCryptoRand(20, defaultPasswordChars);
ubyte[]  salt2 = randomSalt!DefaultCryptoRand(32);
string   singleUse2 = randomToken!DefaultCryptoRand(defaultTokenStrength);
```

Typical Usage Examples
----------------------
See also: [API Reference](http://semitwist.com/dauth/)

```d
import dauth;

// Your code to save/load from a database or other storage:
void saveUserPassword(string user, string passhash) {...}
string loadUserPassword(string user) {...}

void setPassword(string user, char[] pass)
{
	string hashString = makeHash(toPassword(pass)).toString();
	saveUserPassword(user, hashString);
}

bool validateUser(string user, char[] pass)
{
	string hashString = loadUserPassword(user);
	return isSameHash(toPassword(pass), parseHash(hashString));
}
```

In that example:

```setPassword()``` uses DAuth to store randomly-salted password hashes, using the default hashing digest (currently SHA-512), in a forward-compatible ASCII-safe text format. The format is mostly a form of Base64, and similar to [crypt(3)](https://en.wikipedia.org/wiki/Crypt_%28C%29) but more readable and flexible. The hash digest (ex: "SHA512") is stored as part of the ```hashString```, so if you upgrade to a different hashing digest, any existing accounts using the old digest will automatically remain accessible.

```validateUser()``` is automatically compatible with all supported DAuth-style and crypt(3)-style string formats...not just whatever format and digest ```setPassword``` happens to be using. If you wish to restrict the accepted formats and encodings, you can easily do that too.

You may have noticed the passwords are mutable character arrays, not strings. This is for a reason:

DAuth stores passwords in a type named [```Password```](http://semitwist.com/dauth/core.html#Password). This is a reference-counted struct that automatically zero's out the password data in memory before replacing the data or deallocating it. A ```dupPassword(string)``` is provided if you really need it, but this is not recommended (because a string's memory buffer is immutable and usually garbage-collected, and therefore can't be reliably zero'd out). Ultimately, this helps you decrease the likelihood of raw passwords sticking around in memory longer than necessary. Thus, with proper care when reading the password from your user, your user's passwords may be less likely to be exposed in the event of a memory-sniffing attack on your program.

To ensure compatibility with both existing infrastructure and future cryptographic developments, nearly any aspect of the authentication system can be customized:

- Passwords can be hashed using any Phobos-compatible digest (See [std.digest.digest](http://dlang.org/phobos/std_digest_digest.html)).

- Salts can be provided manually, or have a user-defined length.

- Hashes and salts can be stored in any way or format desired. This is because the Hash struct returned by ```makeHash()``` and ```parseHash()``` provides easy access to the hash, the salt, and the digest used.

- The method of combining the salt and raw password can be user-defined (via the optional ```salter``` parameter of ```makeHash()``` and ```isSameHash()```).

- ```Hash!T.toString()``` supports [OutputRange](http://dlang.org/phobos/std_range.html#isOutputRange) sinks, to avoid unnecessary allocations.

- Passwords, salts, and randomized tokens (for one-use URLs) can all be automatically generated, optionally driven by custom Phobos-compatible random number generators.

Here's a more customized usage example:

```d
import std.digest.md;
import std.exception;
import std.random;
import dauth;

// Your code to save/load from a database or other storage:
void saveUserInfo(string user, string digest, string passhash, ubyte[] salt) {...}
string loadUserPassword(string user) {...}
ubyte[] loadUserSalt(string user) {...}
string loadUserDigest(string user) {...}

void setPassword(string user, char[] pass)
{
	// Note: This randomizer is not actually suitable for crypto purposes.
	static MinstdRand rand;
	auto salt = randomSalt(rand, 64);

	// Warning! MD5 should never be used for real passwords.
	auto myHash = makeHash!MD5(pass, salt);
	
	saveUserInfo(user, "MD5", myHash.hash, myHash.salt);
}

bool validateUser(string user, char[] pass)
{
	string hash = loadUserPassword(user);
	ubyte[] salt = loadUserSalt(user);
	ensure(loadUserDigest(user) == "MD5");
	
	return isSameHash!MD5(pass, hash, salt);
}
```

A Note About DAuth's Scope
--------------------------
DAuth isn't intended to directly provide any encryption, hashing, or random number generating algorithms, and tries to leave this up to other libraries (relying on the [Phobos](http://dlang.org/phobos/index.html)-defined protocols for [digests](http://dlang.org/phobos/std_digest_digest.html) and [random number generators](http://dlang.org/phobos/std_random.html)).

At the moment however, DAuth does provide implementations of [SHA-2](http://en.wikipedia.org/wiki/Sha2) and [Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf) because (as of DMD 2.066.0) Phobos lacks a [cryptographically secure psuedorandom number generator](http://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) and didn't gain SHA-2 until recently (v2.066.0). DAuth's intention is to migrate Hash_DRBG over to Phobos and eventually eliminate both that and SHA-2 from DAuth itself.

Notes About DAuth's Priorities
------------------------------
DAuth's default settings and behaviors are specifically chosen with this order of priorities in mind:

1. Flexibility (Top Priority)
2. Overall Security
3. Reliability/Correctness of User Code
4. Cryptographic Security
5. Convenience
6. Efficiency (Lower Priority, but still important)

It may seem strange that "Flexibility" is \#1, even ahead of security, but that's necessary to ensure this library can be used in all potential use-cases (for example, to interface with a legacy system that uses a known-insecure crypto). After all, if this can't be used, it can't provide any security at all.

DAuth does take steps to encourage good security practices, and to help developers achieve it, but ultimately the library's user is responsible for their own security-related choices.

Similarly, it may be surprising that "Cryptographic Security" is ranked below "Reliability/Correctness". However, bugs can often be an even greater threat to overall security than cryptographic weaknesses - and in unpredictable ways.

Convenience is ranked slightly above efficiency because it directly encourages this library's actual usage, and thereby encourages security. Improved efficiency, when needed, can always be tweaked as necessary.

See also
--------
For a good background on authentication, see ["Salted Password Hashing - Doing it Right"](https://crackstation.net/hashing-security.htm)
