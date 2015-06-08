/++
InstaUser-Basic - Salted Hashed Password Library for D
Random generators
+/

module instauser.basic.random;

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
import std.typecons;

import instauser.basic.core;
import instauser.basic.hashdrbg;

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

/++
In bytes of randomness, not length of token.
Must be a multiple of 4. Although, due to usage of base64, using a multiple
of 12 prevents a padding tilde from existing at the end of every token.
+/
enum defaultTokenStrength = 36;

/++
RNGs used with InstaUser must be either a isRandomStream, or
a isUniformRNG input range that emits uint values.
+/
enum isInstaUserRandom(T) =
	isRandomStream!T ||
	(isUniformRNG!T && is(ElementType!T == uint));
alias isDAuthRandom = isInstaUserRandom; /// Temporary backwards-compatibility alias

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

Optional_Params:
Rand - Default value is 'DefaultCryptoRand'

length - Default value is 'defaultPasswordLength'

passwordChars - Default value is 'defaultPasswordChars'
+/
Password randomPassword(Rand = DefaultCryptoRand) (
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if(isInstaUserRandom!Rand)
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
Password randomPassword(Rand = DefaultCryptoRand) (
	ref Rand rand,
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if(isInstaUserRandom!Rand)
out(result)
{
	assert(result.length == length);
}
body
{
	Appender!(ubyte[]) sink;
	randomPassword(rand, sink, length, passwordChars);
	return toPassword(sink.data);
}

///ditto
void randomPassword(Rand = DefaultCryptoRand, Sink)(
	ref Sink sink,
	size_t length = defaultPasswordLength,
	const(ubyte)[] passwordChars = defaultPasswordChars
)
if( isInstaUserRandom!Rand && isOutputRange!(Sink, ubyte) )
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
if( isInstaUserRandom!Rand && isOutputRange!(Sink, ubyte) )
{
	enforce(passwordChars.length >= 2);
	
	static if(isUniformRNG!Rand)
		alias randRange = rand;
	else
		WrappedStreamRNG!(Rand, uint) randRange;
	
	randRange.popFront(); // Ensure fresh data
	foreach(i; 0..length)
	{
		auto charIndex = randRange.front % passwordChars.length;
		sink.put(passwordChars[charIndex]);
		randRange.popFront();
	}
}

version(InstaUserBasic_Unittest)
unittest
{
	unitlog("Testing randomPassword");

	void validateChars(Password pass, immutable(ubyte)[] validChars, size_t length)
	{
		foreach(i; 0..pass.data.length)
		{
			assert(
				validChars.canFind( cast(ubyte)pass.data[i] ),
				text(
					"Invalid char `", pass.data[i],
					"` (ascii ", cast(ubyte)pass.data[i], ") at index ", i,
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
	Password prevPass;
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
		Password pass;
		MinstdRand rand;
		Appender!(ubyte[]) sink;
		
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
		sink = appender!(ubyte[])();
		randomPassword(sink, length, validChars);
		pass = toPassword(sink.data);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!(ubyte[])();
			randomPassword(sink, length, validChars);
			assert(pass.data != sink.data);
		}
		
		// Provided RNG type
		sink = appender!(ubyte[])();
		randomPassword!MinstdRand(sink, length, validChars);
		pass = toPassword(sink.data);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!(ubyte[])();
			randomPassword!MinstdRand(sink, length, validChars);
			assert(pass.data != sink.data);
		}
		
		// Provided RNG object
		sink = appender!(ubyte[])();
		rand = MinstdRand(unpredictableSeed);
		randomPassword(rand, sink, length, validChars);
		pass = toPassword(sink.data);
		assert(pass.length == length);
		validateChars(pass, validChars, length);
		if(validChars.length > 25)
		{
			sink = appender!(ubyte[])();
			randomPassword(rand, sink, length, validChars);
			assert(pass.data != sink.data);
		}
	}
}

/++
Generates a random salt. Necessary for salting passwords.

NEVER REUSE A SALT! This must be called separately EVERY time any user sets
or resets a password. Reusing salts defeats the security of salting passwords.

The length must be a multiple of 4, or this will throw an Exception

Optional_Params:
Rand - Default value is 'DefaultCryptoRand'

length - Default value is 'defaultSaltLength'
+/
Salt randomSalt(Rand = DefaultCryptoRand)(size_t length = defaultSaltLength)
	if(isInstaUserRandom!Rand)
{
	return randomBytes!Rand(length);
}

///ditto
Salt randomSalt(Rand = DefaultCryptoRand)(ref Rand rand, size_t length = defaultSaltLength)
	if(isInstaUserRandom!Rand)
{
	return randomBytes(length, rand);
}

version(InstaUserBasic_Unittest)
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

Optional_Params:
Rand - Default value is 'DefaultCryptoRand'

strength - Default value is 'defaultTokenStrength'
+/
string randomToken(Rand = DefaultCryptoRand)(size_t strength = defaultTokenStrength)
	if(isInstaUserRandom!Rand)
{
	return TokenBase64.encode( randomBytes!Rand(strength) );
}

///ditto
string randomToken(Rand = DefaultCryptoRand)(ref Rand rand, size_t strength = defaultTokenStrength)
	if(isInstaUserRandom!Rand)
{
	return TokenBase64.encode( randomBytes(strength, rand) );
}

version(InstaUserBasic_Unittest)
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

/// numBytes must be a multiple of 4, or this will throw an Exception
ubyte[] randomBytes(Rand = DefaultCryptoRand)(size_t numBytes)
	if(isInstaUserRandom!Rand)
{
	Rand rand;
	rand.initRand();
	return randomBytes(numBytes, rand);
}

///ditto
ubyte[] randomBytes(Rand = DefaultCryptoRand)(size_t numBytes, ref Rand rand)
	if(isInstaUserRandom!Rand)
out(result)
{
	assert(result.length == numBytes);
}
body
{
	enforce(numBytes % 4 == 0, "numBytes must be multiple of 4, not "~to!string(numBytes));
	
	static if(isRandomStream!Rand)
	{
		ubyte[] result;
		result.length = numBytes;
		rand.read(result);
		return result;
	}
	else // Fallback to range version
	{
		rand.popFront(); // Ensure fresh data
		return cast(ubyte[])( rand.take(numBytes/4).array() );
	}
}

private void initRand(Rand)(ref Rand rand)
	if(isInstaUserRandom!Rand)
{
	static if(isSeedable!Rand)
		rand.seed(unpredictableSeed);
}
