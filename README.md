DAuth - Authentication Utility for D
====================================

DAuth is a low-level authentication library for [D](http://dlang.org) with no external dependencies other than the standard library. It accepts any Phobos-compatible [digest](http://dlang.org/phobos/std_digest_digest.html) or [random number generator](http://dlang.org/phobos/std_random.html) algorithm and provides an simple, yet flexible, API to help you easily incorporate secure, upgradable user authentication based on [salted password hashes](http://en.wikipedia.org/wiki/Salt_%28cryptography%29) into your software. You can have as much, or as little, control as you need.

DAuth's main interface is:

- ```makeHash(Password)```: Generates a salted hash for a password. The salt, the hashing ("digest") algorithm, and the salt/password combing ("salter") algorithm can optionally be provided, or left as default. By default, the salt is automatically generated at random.

- ```isPasswordCorrect(Password, Hash)```: Validates a password against an existing salted hash. As with ```makeHash```, everything is optionally customizable. The hashes are compared using a ["length-constant" time](https://crackstation.net/hashing-security.htm) algorithm to thwart timing-based attacks.

The library also provides a forward-compatible string-based hash format for easy storage and retrieval. Additionally, there are functions for randomly generating salts, passwords and single-use tokens.

Note: DAuth isn't intended to provide any encryption, hashing, or random number generating algorithms, and tries to leave this up to other libraries, relying on the [Phobos](http://dlang.org/phobos/index.html)-defined protocols for [digests](http://dlang.org/phobos/std_digest_digest.html) and [random number generators](http://dlang.org/phobos/std_random.html). At the moment, however, DAuth does provide implementations of [SHA-2](http://en.wikipedia.org/wiki/Sha2) and [Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf) because, as of DMD 2.065, D's standard library Phobos doesn't contain any digest better than better than [SHA-1](http://en.wikipedia.org/wiki/SHA-1#Attacks) or any [cryptographically secure random number generator](http://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator). DAuth's intention is to migrate these algorithms over to Phobos.

[DAuth Changelog](https://github.com/Abscissa/DAuth/blob/master/CHANGELOG.md)

Typical Usage
-------------
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
	return isPasswordCorrect(toPassword(pass), parseHash(hashString));
}
```

The above code stores randomly-salted password hashes, using the default hashing digest, in a forward-compatible ASCII-safe text format (mostly a form of Base64). The hash digest (ex: "SHA1") is stored as part of the ```hashString```, so if you upgrade to a different hashing digest, any existing accounts using the old digest will automatically remain accessible.

The passwords are mutable strings for a reason: DAuth stores passwords in a type named ```Password```. This is a reference-counted struct that automatically zero'd out the password data in memory before replacing the data or deallocating it. A ```dupPassword(string)``` is provided if you really need it, but this is not recommended because a string's memory buffer is immutable (and usually garbage-collected), and therefore can't be reliably zero'd out.

To ensure compatibility with both existing infrastructure and future cryptographic developments, nearly any aspect of the authentication system can be customized:

- Passwords can be hashed using any Phobos-compatible digest (See [std.digest.digest](http://dlang.org/phobos/std_digest_digest.html)).

- Salts can be provided manually, or have a user-defined length.

- Hashes and salts can be stored in any way or format desired. This is because the Hash struct returned by ```makeHash()``` and ```parseHash()``` provides easy access to the hash, the salt, and the digest used.

- The method of combining the salt and raw password can be user-defined (via the optional ```salter``` parameter of ```makeHash()``` and ```isPasswordCorrect()```).

- ```Hash!T.toString()``` supports [OutputRange](http://dlang.org/phobos/std_range.html#isOutputRange) sinks, to avoid unnecessary allocations.

- Passwords, salts, and randomized tokens (for one-use URLs) can all be automatically generated, optionally driven by custom Phobos-compatible random number generators.

Here's a somewhat more customized usage example:

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

void setPassword(string user, string pass)
{
	// Note: This randomizer is not actually suitable for crypto purposes.
	static MinstdRand rand;
	auto salt = randomSalt(rand, 64);

	// Warning! MD5 should never be used for real passwords.
	auto myHash = makeHash!MD5(pass, salt);
	
	saveUserInfo(user, "MD5", myHash.hash, myHash.salt);
}

bool validateUser(string user, string pass)
{
	string hash = loadUserPassword(user);
	ubyte[] salt = loadUserSalt(user);
	ensure(loadUserDigest(user) == "MD5");
	
	return isPasswordCorrect!MD5(pass, hash, salt);
}
```

DAuth's Priorities
------------------

DAuth's default settings and behaviors are specifically chosen with this order of priorities in mind:

1. Flexibility (Top Priority)
2. Overall Security
3. Reliability/Correctness of User Code
4. Cryptographic Security
5. Convenience
6. Efficiency (Lower Priority, but still important)

It may seem strange that "Flexibility" is \#1, even ahead of security, but that's necessary to ensure this library can be used in all potential use-cases (for example, to interface with a legacy system that uses a known-insecure crypto). After all, if this can't be used, it can't provide any security at all.

DAuth does take steps to encourage good security practices, and to help developers achieve it, but ultimately the library's user is responsible for their own security-related choices.

Similarly, it may appear odd that "Cryptographic Security" is ranked below "Reliability/Correctness". However, bugs can often be an even greater threat to overall security than cryptographic weaknesses - and in unpredictable ways.

Convenience is ranked slightly above efficiency because it directly encourages this library's actual usage, and thereby encourages security. Improved efficiency, when needed, can always be tweaked as necessary.

See also
--------

For a good background on authentication, see ["Salted Password Hashing - Doing it Right"](https://crackstation.net/hashing-security.htm)
