/++

See also: https://crackstation.net/hashing-security.htm


The default settings and behaviors in this module are specifically chosen
with this order of priorities:

1. Flexibility (Top Priority)
2. Overall Security
3. Reliability/Correctness of User Code
4. Cryptographic Security
5. Convenience
6. Efficiency (Lower Priority, but still important)

Rationale:

It may seem strange that "Flexibility" is #1, even ahead of security, but
that's necessary to ensure this library can be used in all potential
use-cases (for example, to interface with a legacy system that uses
a known-insecure crypto). After all, if this can't be used, it can't provide
any security at all.

DAuth does take steps to encourage good security practices, and to help
developers achieve it, but ultimately the library's user is responsible for
their own security-related choices.

Similarly, it may appear odd that "Cryptographic Security" is ranked below
"Reliability/Correctness". However, bugs can often be an even greater threat to
overall security than cryptographic weaknesses - and in unpredictable ways.

Convenience is ranked slightly above efficiency because it directly encourages
this library's actual usage, and thereby encourages security. Improved
efficiency, when needed, can always be tweaked as necessary.


Typical usage:
----------------------------------------
void setUserPassword(string user, string pass)
{
	auto mySaltedHash = saltedHash(pass);
	string hashString = mySaltedHash.toString();
	saveUserInfo(user, hashString);
}

bool validateUser(string user, string pass)
{
	string hashString = loadUserPassword(user);
	auto mySaltedHash = parseSaltedHash(hashString);
	return isPasswordCorrect(pass, mySaltedHash);
}
----------------------------------------

The above is typical expected usage. It stores randomly-salted password hashes,
in a forward-compatible ASCII-safe text format.

Nearly any aspect of the authentication system can be customized, to ensure
compatibility with both existing infrastructure and future cryptographic
developments:

- Passwords can be hashed using any Phobos-compatibe digest (See std.digest.digest).
- Salts can be provided manually, or have a user-defined length.
- Hashes and salts can be stored in any way or format desired. This is because
the SaltedHash struct returned by saltedHash() and parseSaltedHash() provides
easy access to the hash, the salt, and the digest used.
- The method of combining the salt and raw password can be user-defined.
- The toString supports OutputRange sinks, to avoid unnecessary allocations.
- Passwords, salts, and randomized tokens (for one-use URLs) can all be
automatically generated, optionally driven by custom Phobos-compatible
random number generators.

This is a more customized usage example:
------------------------------------------
import std.digest.md;
import std.random;

void setUserPassword(string user, string pass)
{
	// Note: This randomizer is not actually suitable for crypto purposes.
	static MinstdRand rand;
	auto salt = randomSalt(rand, 64);

	// Note: MD5 should never be used for real passwords.
	auto mySaltedHash = saltedHash!MD5(pass, salt);
	
	saveUserInfo(user, mySaltedHash.hash, mySaltedHash.salt);
}

bool validateUser(string user, string pass)
{
	string hash = loadUserPassword(user);
	string salt = loadUserSalt(user);

	return isPasswordCorrect!MD5(pass, hash, salt);
}
------------------------------------------

+/

module dauth;

import std.algorithm;
import std.array;
import ascii = std.ascii;
import std.base64;
import std.conv;
import std.digest.sha;
import std.exception;
import std.random;
import std.range;

/// Enable DAuth unittests:
///    -unittest -version=Unittest_DAuth
///
/// Enable DAuth unittests, but silence all non-error output:
///    -unittest -version=Unittest_DAuth -version=Unittest_DAuth_Quiet
version(Unittest_DAuth)
{
	version(Unittest_DAuth_Quiet) {} else
		version = Loud_Unittest;
	
	version(Loud_Unittest)
		import std.stdio;
	
	void unitlog(string str)
	{
		version(Loud_Unittest)
		{
			writeln("unittest DAuth: ", str);
			stdout.flush();
		}
	}
}

// Defaults
alias Salt = ubyte[];
alias DefaultCryptoRand = Mt19937; /// Bad choice, but I'm not sure if Phobos has a crypto-oriented random.
alias DefaultDigest = SHA1; /// Bad choice, but the best Phobos currently has.
alias DefaultDigestClass = WrapperDigest!DefaultDigest;
alias TokenBase64 = Base64Impl!('-', '_', '~');

/// In characters. Default length of randomly-generated passwords.
enum defaultPasswordLength = 20;

/++
Punctuation is not included in generated passwords by default. Technically,
this is slightly less secure for a given password length, but it prevents
syntax-related bugs when a generated password is stored in a (properly-secured)
text-based configuration file.

If you know how the generated password will be used, you can add known-safe
punctuation to this when you call randomPassword.
+/
enum defaultPasswordChars = cast(immutable(ubyte)[]) (ascii.letters ~ ascii.digits);

/// In bytes. Must be a multiple of 4.
enum defaultSaltLength = 32;

/// In bytes of randomness, not length of token.
/// Must be a multiple of 4. Although, due to usage of base64, using a multiple
/// of 12 prevents a padding tilde from existing at the end of every token.
enum defaultTokenStrength = 36;

/// Like std.digest.digest.isDigest, but also accepts OO-style digests
/// (ie. classes deriving from interface std.digest.digest.Digest)
template isAnyDigest(Digest)
{
	enum isAnyDigest =
		isDigest!Digest ||
		is(Digest : std.digest.digest.Digest);
}

version(Unittest_DAuth)
unittest
{
	struct Foo {}
	static assert(isAnyDigest!SHA1);
	static assert(isAnyDigest!SHA1Digest);
	static assert(!isAnyDigest!Foo);
	static assert(!isAnyDigest!Object);
}

/// Like std.digest.digest.DigestType, but also accepts OO-style digests
/// (ie. classes deriving from interface std.digest.digest.Digest)
template AnyDigestType(Digest)
{
	static assert(isAnyDigest!Digest,
		Digest.stringof ~ " is not a template-style or OO-style digest (fails isAnyDigest!T)");
	
	static if(isDigest!Digest)
		alias AnyDigestType = DigestType!Digest;
	else
		alias AnyDigestType = ubyte[];
}

version(Unittest_DAuth)
unittest
{
	struct Foo {}
	static assert( is(AnyDigestType!SHA1 == ubyte[20]) );
	static assert( is(AnyDigestType!SHA1Digest == ubyte[]) );
	static assert( !is(AnyDigestType!Foo) );
	static assert( !is(AnyDigestType!Object) );
}

/// Tests if the type is an instance of struct SaltedHash(Digest)
template isSaltedHash(T)
{
	enum isSaltedHash =
		is( typeof(T.init.digest) ) &&
		is( SaltedHash!(typeof(T.init.digest)) ) &&
		is( SaltedHash!(typeof(T.init.digest)) == T );
}

version(Unittest_DAuth)
unittest
{
	struct Foo {}
	struct Bar(T) { T digest; }

	static assert( isSaltedHash!(SaltedHash!SHA1) );
	static assert( isSaltedHash!(SaltedHash!SHA1Digest) );

	static assert( !isSaltedHash!Foo              );
	static assert( !isSaltedHash!(Bar!int)        );
	static assert( !isSaltedHash!(Bar!Object)     );
	static assert( !isSaltedHash!(Bar!SHA1)       );
	static assert( !isSaltedHash!(Bar!SHA1Digest) );
}

/// Contains all the relevent information for a salted hash.
/// Note that the digest type can be obtained via typeof(mySaltedHash.digest).
struct SaltedHash(Digest) if(isAnyDigest!Digest)
{
	Salt salt;       /// The salt that was used.
	string password; /// Plaintext version of the password.
	
	/// The hash of the salted password. To obtain a printable DB-friendly
	/// string, pass this to std.digest.digest.toHexString.
	AnyDigestType!Digest hash;
	
	/// The digest that was used for hashing.
	/// Note, this may get reset and reused.
	Digest digest;
	
	/// Encodes the digest, salt and hash into a convenient forward-compatible
	/// string format, ready for insertion into a database.
	string toString()
	{
		Appender!string sink;
		toString(sink);
		return sink.data;
	}

	///ditto
	void toString(Sink)(ref Sink sink) if(isOutputRange!(Sink, const(char)))
	{
		sink.put('[');

		//TODO: Encode digest type
		sink.put('T');
		sink.put('B');
		sink.put('D');

		sink.put(']');
		Base64.encode(salt, sink);
		sink.put('$');
		Base64.encode(hash, sink);
	}
}

/++
Generates a salted password using any Phobos-compatible digest, default being SHA1.

(Note: SHA1 is a poor choice for password hashes since it's fast
and therefore susceptible to parallelized (ex: GPU) brute-force attack.
A cryptographically-slow algorithm designed for password hashing should
be used instead, but SHA1 is the best Phobos has at the moment.)

Supports both template-style and OO-style digests. See the documentation of
std.digest.digest for details.

Password and salt are optional. They will be generated at random if not provided.
+/
SaltedHash!Digest saltedHash
	(Digest = DefaultDigest)
	(string password = randomPassword(), Salt salt = randomSalt())
	if(isDigest!Digest)
{
	Digest digest;
	return saltedHashImpl(digest, password, salt);
}

///ditto
SaltedHash!Digest saltedHash(Digest digest = new DefaultDigestClass(),
	string password = randomPassword(), Salt salt = randomSalt())
{
	return saltedHashImpl(digest, password, salt);
}

private SaltedHash!Digest saltedHashImpl(Digest)(ref Digest digest, string password, Salt salt)
	if(isAnyDigest!Digest)
{
	SaltedHash!Digest ret;
	ret.digest   = digest;
	ret.salt     = salt;
	ret.password = password;
	
	static if(isDigest!Digest) // template-based digest
		ret.digest.start();
	else
		ret.digest.reset(); // OO-based digest
	
	//TODO: This needs to be customizable (also update isPasswordCorrect)
	ret.digest.put(cast(immutable(ubyte)[])salt);
	ret.digest.put(cast(immutable(ubyte)[])password);

	ret.hash = ret.digest.finish();
	
	return ret;
}

/// Parses a string that was encoded by SaltedHash.toString.
///
/// Only OO-style digests are used since the digest is specified in the string
/// and therefore only known at runtime.
///
/// Throws ConvException if the string is malformed.
SaltedHash!(std.digest.digest.Digest) parseSaltedHash(string str)
{
	// No need to mess with UTF
	auto bytes = cast(immutable(ubyte)[]) str;
	
	void eat(char c)
	{
		enforceEx!ConvException(!bytes.empty);
		enforceEx!ConvException(bytes.front == cast(ubyte)c);
		bytes.popFront();
	}
	
	eat('[');

	//TODO: Decode and handle digest type
	eat('T');
	eat('B');
	eat('D');

	eat(']');
	
	auto parts = bytes.findSplit(['$']);
	enforceEx!ConvException( !parts[0].empty && !parts[1].empty && !parts[2].empty );
	auto salt = parts[0];
	auto hash = parts[2];
	
	SaltedHash!(std.digest.digest.Digest) result;
	result.salt     = Base64.decode(salt);
	result.password = null;
	result.hash     = Base64.decode(hash);
	result.digest   = new SHA1Digest(); //TODO: Use digest type specified in the string
	
	return result;
}

/// Validates a password against an existing salted hash.
bool isPasswordCorrect(Hash)(string password, SaltedHash hash)
{
	auto testHash = saltedHash(hash.digest, password, hash.salt);
	return testHash.hash == hash.hash;
}

///ditto
bool isPasswordCorrect(Digest = DefaultDigest)
	(string password, DigestType!Digest hash, Salt salt)
	if(isDigest!Digest)
{
	Digest digest;
	auto testHash = saltedHash(digest, password, salt);
	return testHash.hash == hash;
}

///ditto
bool isPasswordCorrect(string password,
	ubyte[] hash, Salt salt, Digest digest = new DefaultDigestClass())
{
	auto testHash = saltedHash(digest, password, salt);
	return testHash.hash == hash;
}

version(Unittest_DAuth)
unittest
{
	// For validity of sanity checks, these sha1 and base64 strings
	// were NOT generated using Phobos.
	enum plainText1      = "hello world";
	enum sha1Hash1       = cast(ubyte[20]) x"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
	enum sha1Hash1Base64 = "Kq5sNclPz7QV2+lfQIuc6R7oRu0=";

	enum plainText2      = "some salt";
	enum sha1Hash2       = cast(ubyte[20]) x"78bc8b0e186b0aa698f12dc27736b492e4dacfc8";
	enum sha1Hash2Base64 = "eLyLDhhrCqaY8S3Cdza0kuTaz8g=";
	
	unitlog("Sanity checking unittest's data");
	assert(sha1Of(plainText1) == sha1Hash1);
	assert(sha1Of(plainText2) == sha1Hash2);
	assert(Base64.encode(sha1Hash1) == sha1Hash1Base64);
	assert(Base64.encode(sha1Hash2) == sha1Hash2Base64);

	unitlog("Testing SaltedHash.toString");
	SaltedHash!SHA1 result1;
	result1.hash = cast(AnyDigestType!SHA1) sha1Hash1;
	result1.salt = cast(Salt)               sha1Hash2;
	assert( result1.toString() == text("[TBD]", sha1Hash2Base64, "$", sha1Hash1Base64) );
	
	unitlog("Testing saltedHash(pass, salt)");
	auto result2 = saltedHash!SHA1(plainText1, sha1Hash2);
	auto result3 = saltedHash(new SHA1Digest(), plainText1, cast(Salt)sha1Hash2);

	assert(result2.password   == result3.password);
	assert(result2.salt       == result3.salt);
	assert(result2.hash       == result3.hash);
	assert(result2.toString() == result3.toString());

	assert(result2.salt == result1.salt);
	
	unitlog("Testing saltedHash(void)");
	auto resultRand1 = saltedHash!SHA1();
	auto resultRand2 = saltedHash!SHA1();

	assert(resultRand1.password != result1.password);
	assert(resultRand1.salt != result1.salt);

	assert(resultRand1.password != resultRand2.password);
	assert(resultRand1.salt != resultRand2.salt);
	assert(resultRand1.hash != resultRand2.hash);

	unitlog("Testing parseSaltedHash(void)");
	auto result2Parsed = parseSaltedHash( result2.toString() );
	assert(result2Parsed.password is null);
	assert(result2.salt       == result2Parsed.salt);
	assert(result2.hash       == result2Parsed.hash);
	assert(result2.toString() == result2Parsed.toString());
}

/++
Generates a random password.

This is limited to generating ASCII passwords. This is because including
non-ASCII characters in generated passwords is more complex, more error-prone,
more likely to trigger latent unicode bugs in other systems, and not
particularly useful anyway.

Throws an Exception if passwordChars.length isn't at least 2.

USE THIS RESPONSIBLY! NEVER EMAIL THE PASSWORD! Emailing a generated password
to a user is a highly insecure practice and should NEVER be done. However,
there are other times when generating a password may be reasonable, so this is
provided as a convenience.
+/
string randomPassword(Rand = DefaultCryptoRand) (
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if(isUniformRNG!Rand)
out(result)
{
	assert(result.length == length);
}
body
{
	Rand rand;
	rand.initRand();
	return randomPassword(rand, length, passwordChars);
}

///ditto
string randomPassword(Rand = DefaultCryptoRand) (
	ref Rand rand,
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if(isUniformRNG!Rand)
out(result)
{
	assert(result.length == length);
}
body
{
	Appender!string sink;
	randomPassword(rand, sink, length, passwordChars);
	return sink.data;
}

///ditto
void randomPassword(Rand = DefaultCryptoRand, Sink)(
	ref Sink sink,
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if( isUniformRNG!Rand && isOutputRange!(Sink, const(char)) )
{
	Rand rand;
	rand.initRand();
	randomPassword(rand, sink, length, passwordChars);
}

///ditto
void randomPassword(Rand = DefaultCryptoRand, Sink) (
	ref Rand rand, ref Sink sink,
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if( isUniformRNG!Rand && isOutputRange!(Sink, const(char)) )
{
	enforce(passwordChars.length >= 2);
	
	rand.popFront(); // Ensure fresh data
	foreach(i; 0..length)
	{
		auto charIndex = rand.front % passwordChars.length;
		sink.put(passwordChars[charIndex]);
		rand.popFront();
	}
}

version(Unittest_DAuth)
unittest
{
	unitlog("Testing randomPassword");

	void validateChars(string pass, immutable(ubyte)[] validChars, size_t length)
	{
		foreach(i; 0..pass.length)
		{
			assert(
				validChars.canFind( cast(ubyte)pass[i] ),
				text(
					"Invalid char `", pass[i],
					"` (ascii ", cast(ubyte)pass[i], ") at index ", i,
					" in password length ", length,
					". Valid char set: ", validChars
				)
			);
		}
	}
	
	// Ensure non-purity
	assert(randomPassword() != randomPassword());
	assert(randomPassword!MinstdRand() != randomPassword!MinstdRand());
	auto randA = MinstdRand(unpredictableSeed);
	auto randB = MinstdRand(unpredictableSeed);
	assert(randomPassword(randA) != randomPassword(randB));
	
	// Ensure length, valid chars and non-purity:
	//     Default RNG, length and charset. Non-sink.
	string prevPass;
	foreach(i; 0..10)
	{
		auto pass = randomPassword();
		assert(pass.length == defaultPasswordLength);
		validateChars(pass, defaultPasswordChars, defaultPasswordLength);
		
		assert(pass != prevPass);
		prevPass = pass;
	}

	// Test argument-checking
	assertThrown(randomPassword(5, []));
	assertThrown(randomPassword(5, ['X']));

	// Ensure length, valid chars and non-purity:
	//     Default and provided RNGs. With/without sink. Various lengths and charsets.
	auto charsets = [
		defaultPasswordChars,
		defaultPasswordChars ~ cast(immutable(ubyte)[])".,<>",
		cast(immutable(ubyte)[]) "abc123",
		cast(immutable(ubyte)[]) "XY"
	];
	foreach(validChars; charsets)
	foreach(length; [defaultPasswordLength, 5, 2])
	foreach(i; 0..2)
	{
		string pass;
		MinstdRand rand;
		Appender!string sink;
		
		// -- Non-sink -------------

		// Default RNG
		pass = randomPassword(length, validChars);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
			assert(pass != randomPassword(length, validChars));
		
		// Provided RNG type
		pass = randomPassword!MinstdRand(length, validChars);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
			assert(pass != randomPassword!MinstdRand(length, validChars));
		
		// Provided RNG object
		rand = MinstdRand(unpredictableSeed);
		pass = randomPassword(rand, length, validChars);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
			assert(pass != randomPassword(rand, length, validChars));
		
		// -- With sink -------------

		// Default RNG
		sink = appender!string();
		randomPassword(sink, length, validChars);
		pass = sink.data;
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!string();
			randomPassword(sink, length, validChars);
			assert(pass != sink.data);
		}
		
		// Provided RNG type
		sink = appender!string();
		randomPassword!MinstdRand(sink, length, validChars);
		pass = sink.data;
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!string();
			randomPassword!MinstdRand(sink, length, validChars);
			assert(pass != sink.data);
		}
		
		// Provided RNG object
		sink = appender!string();
		rand = MinstdRand(unpredictableSeed);
		randomPassword(rand, sink, length, validChars);
		pass = sink.data;
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!string();
			randomPassword(rand, sink, length, validChars);
			assert(pass != sink.data);
		}
	}
}

/++
Generates a random salt. Necessary for salting passwords.

NEVER REUSE A SALT! This must be called separately EVERY time any user sets
or resets a password. Reusing salts defeats the security of salting passwords.

The length must be a multiple of 4, or this will throw an Exception

WARNING! Mt19937 (the default here) is not a "Cryptographically secure
pseudorandom number generator"
+/
Salt randomSalt(Rand = DefaultCryptoRand)(size_t length = defaultSaltLength)
	if(isUniformRNG!Rand)
{
	return randomBytes!Rand(length);
}

///ditto
Salt randomSalt(Rand = DefaultCryptoRand)(ref Rand rand, size_t length = defaultSaltLength)
	if(isUniformRNG!Rand)
{
	return randomBytes(length, rand);
}

version(Unittest_DAuth)
unittest
{
	unitlog("Testing randomSalt");

	// Ensure non-purity
	assert(randomSalt() != randomSalt());
	assert(randomSalt!MinstdRand() != randomSalt!MinstdRand());
	auto randA = MinstdRand(unpredictableSeed);
	auto randB = MinstdRand(unpredictableSeed);
	assert(randomSalt(randA) != randomSalt(randB));
	
	// Ensure zero-length case doesn't blow up
	assert(randomSalt(0).empty);
	assert(randomSalt(randA, 0).empty);

	// Test argument-checking (length not multiple of 4)
	assertThrown(randomSalt(5));
	assertThrown(randomSalt(6));
	assertThrown(randomSalt(7));

	// Ensure length and non-purity:
	//     Default and provided RNGs. Various lengths.
	foreach(length; [defaultSaltLength, 20, 8])
	foreach(i; 0..2)
	{
		Salt salt;
		
		// Default RNG
		salt = randomSalt(length);
		assert(salt.length == length);
		assert(salt != randomSalt(length));
		
		// Provided RNG type
		salt = randomSalt!MinstdRand(length);
		assert(salt.length == length);
		assert(salt != randomSalt!MinstdRand(length));
		
		// Provided RNG object
		auto rand = MinstdRand(unpredictableSeed);
		salt = randomSalt(rand, length);
		assert(salt.length == length);
		assert(salt != randomSalt(rand, length));
	}
}

/++
Generates a random token. Useful for temporary one-use URLs, such as in
email confirmations.

The strength is the number of bytes of randomness in the token.
Note this is NOT the length of the token string returned, since this token is
base64-encoded (using an entirely URI-safe version that doesn't need escaping)
from the raw random bytes.

The strength must be a multiple of 4, or this will throw an Exception

WARNING! Mt19937 (the default here) is not a "Cryptographically secure
pseudorandom number generator"
+/
string randomToken(Rand = DefaultCryptoRand)(size_t strength = defaultTokenStrength)
	if(isUniformRNG!Rand)
{
	return TokenBase64.encode( randomBytes!Rand(strength) );
}

///ditto
string randomToken(Rand = DefaultCryptoRand)(ref Rand rand, size_t strength = defaultTokenStrength)
	if(isUniformRNG!Rand)
{
	return TokenBase64.encode( randomBytes(strength, rand) );
}

version(Unittest_DAuth)
unittest
{
	unitlog("Testing randomToken");
	
	// Ensure non-purity
	assert(randomToken() != randomToken());
	assert(randomToken!MinstdRand() != randomToken!MinstdRand());
	auto randA = MinstdRand(unpredictableSeed);
	auto randB = MinstdRand(unpredictableSeed);
	assert(randomToken(randA) != randomToken(randB));
	
	// Ensure zero-strength case doesn't blow up
	assert(randomToken(0).empty);
	assert(randomToken(randA, 0).empty);

	// Test argument-checking (strength not multiple of 4)
	assertThrown(randomToken(5));
	assertThrown(randomToken(6));
	assertThrown(randomToken(7));

	// Ensure length, valid chars and non-purity:
	//     Default and provided RNGs. Various lengths.
	foreach(strength; [defaultTokenStrength, 20, 8])
	foreach(i; 0..2)
	{
		string token;
		MinstdRand rand;
		
		import std.math : ceil;
		
		// Default RNG
		token = randomToken(strength);
		// 6 bits per Base64-encoded byte vs. 8 bits per input (strength) byte
		// (with input length rounded up to the next multiple of 3)
		assert(token.length * 6 == (ceil(strength/3.0L)*3) * 8);
		assert(TokenBase64.decode(token));
		assert(token != randomToken(strength));
		
		// Provided RNG type
		token = randomToken!MinstdRand(strength);
		assert(token.length * 6 == (ceil(strength/3.0L)*3) * 8);
		assert(TokenBase64.decode(token));
		assert(token != randomToken!MinstdRand(strength));
		
		// Provided RNG object
		rand = MinstdRand(unpredictableSeed);
		token = randomToken(rand, strength);
		assert(token.length * 6 == (ceil(strength/3.0L)*3) * 8);
		assert(TokenBase64.decode(token));
		assert(token != randomToken(rand, strength));
	}
}

/// WARNING! Mt19937 (the default here) is not a "Cryptographically secure
/// pseudorandom number generator"
///
/// numBytes must be a multiple of 4, or this will throw an Exception
//TODO: Get a Cryptographically secure pseudorandom number generator
ubyte[] randomBytes(Rand = DefaultCryptoRand)(size_t numBytes)
	if(isUniformRNG!Rand)
{
	Rand rand;
	rand.initRand();
	return randomBytes(numBytes, rand);
}

///ditto
ubyte[] randomBytes(Rand = DefaultCryptoRand)(size_t numBytes, ref Rand rand)
	if(isUniformRNG!Rand)
out(result)
{
	assert(result.length == numBytes);
}
body
{
	enforce(numBytes % 4 == 0, "numBytes must be multiple of 4, not "~to!string(numBytes));
	rand.popFront(); // Ensure fresh data
	return cast(ubyte[])( rand.take(numBytes/4).array() );
}

private void initRand(Rand)(ref Rand rand)
	if(isUniformRNG!Rand)
{
	if(isSeedable!Rand)
		rand.seed(unpredictableSeed);
}

alias FooTempl = SaltedHash!SHA1;
alias FooOO    = SaltedHash!SHA1Digest;

void main()
{
	import std.stdio;
	FooTempl a; FooOO b;
	writeln("12 random bytes: ", randomBytes(8).toHexString());
	writeln("randomToken():   ", randomToken());
	writeln("saltedHash():    ", saltedHash());
	
	auto str =
		"[TBD]"~
		cast(string) Base64.encode( cast(immutable(ubyte)[]) "the salt" )~
		"$"~
		cast(string) Base64.encode( cast(immutable(ubyte)[]) "the hash" );
	writeln(str);
	auto sh = parseSaltedHash(str);
	writeln(sh.salt);
	writeln(sh.hash);
	
}
