/++
DAuth - Authentication Utility for D
Core package

Main module: $(LINK2 index.html,dauth)$(BR)
+/
module dauth.core;

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

import dauth.random : randomSalt;
import dauth.hashdrbg;

// Only use dauth.sha if SHA-2 isn't in Phobos (ie, DMD 2.065 and below)
static if(!is(std.digest.sha.SHA512))
{
	import dauth.sha;

	private alias SHA1 = dauth.sha.SHA1;
	private alias SHA1Digest = dauth.sha.SHA1Digest;
	private alias sha1Of = dauth.sha.sha1Of;
}

version(DAuth_Unittest)
{
	version(DAuth_Unittest_Quiet) {} else
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

version(DAuth_AllowWeakSecurity) {} else
{
	version = DisallowWeakSecurity;
}

alias Salt = ubyte[]; /// Salt type
alias Salter(TDigest) = void delegate(ref TDigest, Password, Salt); /// Convenience alias for salter delegates.
alias DefaultCryptoRand = HashDRBGStream!(SHA512, "DAuth"); /// Default is Hash_DRBG using SHA-512
alias DefaultDigest = SHA512; /// Default is SHA-512
alias DefaultDigestClass = WrapperDigest!DefaultDigest; /// OO-style version of 'DefaultDigest'.
alias TokenBase64 = Base64Impl!('-', '_', '~'); /// Implementation of Base64 engine used for tokens.

/// Default implementation of 'digestCodeOfObj' for DAuth-style hash strings.
/// See 'Hash!(TDigest).toString' for more info.
string defaultDigestCodeOfObj(Digest digest)
{
	if     (cast( CRC32Digest      )digest) return "CRC32";
	else if(cast( MD5Digest        )digest) return "MD5";
	else if(cast( RIPEMD160Digest  )digest) return "RIPEMD160";
	else if(cast( SHA1Digest       )digest) return "SHA1";
	else if(cast( SHA224Digest     )digest) return "SHA224";
	else if(cast( SHA256Digest     )digest) return "SHA256";
	else if(cast( SHA384Digest     )digest) return "SHA384";
	else if(cast( SHA512Digest     )digest) return "SHA512";
	else if(cast( SHA512_224Digest )digest) return "SHA512_224";
	else if(cast( SHA512_256Digest )digest) return "SHA512_256";
	else
		throw new UnknownDigestException("Unknown digest type");
}

/// Default implementation of 'digestFromCode' for DAuth-style hash strings.
/// See 'parseHash' for more info.
Digest defaultDigestFromCode(string digestCode)
{
	switch(digestCode)
	{
	case "CRC32":      return new CRC32Digest();
	case "MD5":        return new MD5Digest();
	case "RIPEMD160":  return new RIPEMD160Digest();
	case "SHA1":       return new SHA1Digest();
	case "SHA224":     return new SHA224Digest();
	case "SHA256":     return new SHA256Digest();
	case "SHA384":     return new SHA384Digest();
	case "SHA512":     return new SHA512Digest();
	case "SHA512_224": return new SHA512_224Digest();
	case "SHA512_256": return new SHA512_256Digest();
	default:
		throw new UnknownDigestException("Unknown digest code");
	}
}

/// Default implementation of 'digestCodeOfObj' for Unix crypt-style hash strings.
/// See 'Hash!(TDigest).toString' for more info.
string defaultDigestCryptCodeOfObj(Digest digest)
{
	if     (cast( MD5Digest    )digest) return "1";
	else if(cast( SHA256Digest )digest) return "5";
	else if(cast( SHA512Digest )digest) return "6";
	else
		throw new UnknownDigestException("Unknown digest type");
}

/// Default implementation of 'digestFromCode' for Unix crypt-style hash strings.
/// See 'parseHash' for more info.
Digest defaultDigestFromCryptCode(string digestCode)
{
	switch(digestCode)
	{
	case "":   throw new UnknownDigestException(`Old crypt-DES not currently supported`);
	case "1":  return new MD5Digest();
	case "5":  return new SHA256Digest();
	case "6":  return new SHA512Digest();
	default:
		throw new UnknownDigestException("Unknown digest code");
	}
}

/// Default salter for 'makeHash' and 'isPasswordCorrect'.
void defaultSalter(TDigest)(ref TDigest digest, Password password, Salt salt)
	if(isAnyDigest!TDigest)
{
	digest.put(cast(immutable(ubyte)[])salt);
	digest.put(password.data);
}

/++
Note, this only checks Phobos's RNG's and digests, and only by type. This
works on a blacklist basis - it blindly accepts any Phobos-compatible RNG
or digest it does not know about. This is only supplied as a convenience. It
is always your own responsibility to select an appropriate algorithm for your
own needs.

And yes, unfortunately, this does currently rule out all RNG's and digests
currently in Phobos (as of v2.065). They are all known to be fairly weak
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
bool isKnownWeak(T)() if(isDigest!T || isSomeRandom!T)
{
	return
		is(T == CRC32) ||
		is(T == MD5) ||
		is(T == RIPEMD160) ||
		is(T == SHA1) ||
		
		// Requires to-be-released DMD 2.066:
		//__traits(isSame, TemplateOf!T, LinearCongruentialEngine) ||
		//__traits(isSame, TemplateOf!T, MersenneTwisterEngine) ||
		//__traits(isSame, TemplateOf!T, XorshiftEngine);
		is(T == MinstdRand0) ||
		is(T == MinstdRand) ||
		is(T == Mt19937) ||
		is(T == Xorshift32) ||
		is(T == Xorshift64) ||
		is(T == Xorshift96) ||
		is(T == Xorshift128) ||
		is(T == Xorshift160) ||
		is(T == Xorshift192) ||
		is(T == Xorshift);
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

private void validateStrength(T)() if(isDigest!T || isSomeRandom!T)
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

private void validateStrength(Digest digest)
{
	version(DisallowWeakSecurity)
	{
		enforce(!isKnownWeak(digest),
			new KnownWeakException(defaultDigestCodeOfObj(digest)));
	}
}

/// Thrown whenever a digest type cannot be determined.
/// For example, when the provided (or default) 'digestCodeOfObj' or 'digestFromCode'
/// delegates fail to find a match. Or when passing isPasswordCorrect a
/// Hash!Digest with a null 'digest' member (which prevents it from determining
/// the correct digest to match with).
class UnknownDigestException : Exception
{
	this(string msg) { super(msg); }
}

/// Thrown when a known-weak algortihm or setting it attempted, UNLESS
/// compiled with '-version=DAuth_AllowWeakSecurity'
class KnownWeakException : Exception
{
	static enum message =
		"This is known to be weak for salted password hashing. "~
		"If you understand and accept the risks, you can force DAuth "~
		"to allow it with -version=DAuth_AllowWeakSecurity";
	
	this(string algoName)
	{
		super(algoName ~ " - " ~ message);
	}
}

/// Like std.digest.digest.isDigest, but also accepts OO-style digests
/// (ie. classes deriving from interface std.digest.digest.Digest)
template isAnyDigest(TDigest)
{
	enum isAnyDigest =
		isDigest!TDigest ||
		is(TDigest : Digest);
}

version(DAuth_Unittest)
unittest
{
	struct Foo {}
	static assert(isAnyDigest!SHA1);
	static assert(isAnyDigest!SHA1Digest);
	static assert(isAnyDigest!SHA256);
	static assert(isAnyDigest!SHA256Digest);
	static assert(!isAnyDigest!Foo);
	static assert(!isAnyDigest!Object);
}

/// Like std.digest.digest.DigestType, but also accepts OO-style digests
/// (ie. classes deriving from interface std.digest.digest.Digest)
template AnyDigestType(TDigest)
{
	static assert(isAnyDigest!TDigest,
		TDigest.stringof ~ " is not a template-style or OO-style digest (fails isAnyDigest!T)");
	
	static if(isDigest!TDigest)
		alias AnyDigestType = DigestType!TDigest;
	else
		alias AnyDigestType = ubyte[];
}

version(DAuth_Unittest)
unittest
{
	struct Foo {}
	static assert( is(AnyDigestType!SHA1 == ubyte[20]) );
	static assert( is(AnyDigestType!SHA1Digest == ubyte[]) );
	static assert( is(AnyDigestType!SHA512 == ubyte[64]) );
	static assert( is(AnyDigestType!SHA512Digest == ubyte[]) );
	static assert( !is(AnyDigestType!Foo) );
	static assert( !is(AnyDigestType!Object) );
}

/// Tests if the type is an instance of struct Hash(some digest)
template isHash(T)
{
	enum isHash = is( Hash!(TemplateArgsOf!(T)[0]) == T );
}

version(DAuth_Unittest)
unittest
{
	struct Foo {}
	struct Bar(T) { T digest; }

	static assert( isHash!(Hash!SHA1) );
	static assert( isHash!(Hash!SHA1Digest) );
	static assert( isHash!(Hash!SHA512) );
	static assert( isHash!(Hash!SHA512Digest) );

	static assert( !isHash!Foo              );
	static assert( !isHash!(Bar!int)        );
	static assert( !isHash!(Bar!Object)     );
	static assert( !isHash!(Bar!SHA1)       );
	static assert( !isHash!(Bar!SHA1Digest) );
}

/// Retreive the digest type of a struct Hash(some digest)
template DigestOf(T) if(isHash!T)
{
	alias DigestOf = TemplateArgsOf!(T)[0];
}

version(DAuth_Unittest)
unittest
{
	static assert(is( DigestOf!(Hash!SHA1  ) == SHA1  ));
	static assert(is( DigestOf!(Hash!SHA512) == SHA512));
	static assert(is( DigestOf!(Hash!Digest) == Digest));
}

string getDigestCode(TDigest)(string delegate(Digest) digestCodeOfObj, TDigest digest)
	if(isAnyDigest!TDigest)
{
	static if(is(TDigest : Digest))
		return digestCodeOfObj(digest);
	else
	{
		auto digestObj = new WrapperDigest!TDigest();
		return digestCodeOfObj(digestObj);
	}
}

/++
A reference-counted type for passwords. The memory containing the password
is automatically zeroed-out when there are no more references or when
a new password is assigned.

If you keep any direct references to Password.data, be aware it may get cleared.

The payload is a private struct that supports the following:

	@property ubyte[] data(): Retrieve the actual plaintext password

	@property size_t length() const: Retrieve the password length

	void opAssign(PasswordData rhs): Assignment

	void opAssign(ubyte[] rhs): Assignment

	~this(): Destructor
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

/// Constructs a Password from a ubyte[].
/// Mainly provided for syntactic consistency with 'toPassword(char[])'.
Password toPassword(ubyte[] password)
{
	return Password(password);
}

/// Constructs a Password from a char[] so you don't have to cast to ubyte[],
/// and don't accidentally cast away immutability.
Password toPassword(char[] password)
{
	return Password(cast(ubyte[])password);
}

/// This function exists as a convenience in case you need it, HOWEVER it's
/// recommended to design your code so you DON'T need to use this (use
/// toPassword instead):
///
/// Using this to create a Password cannot protect the in-memory data of your
/// original string because a string's data is immutable (this function must
/// .dup the memory).
///
/// While immutability usually improves safety, you should avoid ever storing
/// unhashed passwords in immutables because they cannot be reliably
/// zero-ed out.
Password dupPassword(string password)
{
	return toPassword(password.dup);
}

/// Contains all the relevant information for a salted hash.
/// Note the digest type can be obtained via DigestOf!(SomeHashType).
struct Hash(TDigest) if(isAnyDigest!TDigest)
{
	Salt salt; /// The salt that was used.
	
	/// The hash of the salted password. To obtain a printable DB-friendly
	/// string, pass this to std.digest.digest.toHexString.
	AnyDigestType!TDigest hash;
	
	/// The digest that was used for hashing.
	TDigest digest;
	
	/// Encodes the digest, salt and hash into a convenient forward-compatible
	/// string format, ready for insertion into a database.
	///
	/// To support additional digests besides the built-in (Phobos's CRC32, MD5,
	/// RIPEMD160 and SHA), supply a custom delegate for digestCodeOfObj.
	/// Your custom digestCodeOfObj only needs to handle OO-style digests.
	/// As long as the OO-style digests were created using Phobos's
	/// WrapperDigest template, the template-style version will be handled
	/// automatically. You can defer to DAuth's defaultDigestCodeOfObj to
	/// handle the built-in digests.
	///
	/// Example:
	/// -------------------
	/// import std.digest.digest;
	/// import dauth;
	/// 
	/// struct BBQ42 {...}
	/// static assert(isDigest!BBQ42);
	/// alias BBQ42Digest = WrapperDigest!BBQ42;
	/// 
	/// string customDigestCodeOfObj(Digest digest)
	/// {
	///     if     (cast(BBQ42Digest)digest) return "BBQ42";
	///     else if(cast(FAQ17Digest)digest) return "FAQ17";
	///     else
	///         return defaultDigestCodeOfObj(digest);
	/// }
	/// 
	/// void doStuff(Hash!BBQ42 hash)
	/// {
	///     writeln( hash.toString(&customDigestCodeOfObj) );
	/// }
	/// -------------------
	string toString(string delegate(Digest) digestCodeOfObj = toDelegate(&defaultDigestCodeOfObj))
	{
		Appender!string sink;
		toString(sink, digestCodeOfObj);
		return sink.data;
	}

	///ditto
	void toString(Sink)(ref Sink sink,
		string delegate(Digest) digestCodeOfObj = toDelegate(&defaultDigestCodeOfObj))
		if(isOutputRange!(Sink, const(char)))
	{
		sink.put('[');
		sink.put(getDigestCode(digestCodeOfObj, digest));
		sink.put(']');
		Base64.encode(salt, sink);
		sink.put('$');
		Base64.encode(hash, sink);
	}

	/++
	Just like toString, but instead of standard DAuth-style format, the
	output string is in the crypt(3)-style format.
	
	The crypt(3) format does not support all hash types, and DAuth doesn't
	necessarily support all possible forms of crypt(3) hashes (although it
	does strive to support as many as possible).
	
	DAuth currently supports crypt(3)-style format for MD5, SHA256 and
	SHA512 hashes. Other hashes (unless manually handled by a custom
	digestCodeOfObj) will cause an UnknownDigestException to be thrown.
	
	The default digestCodeOfObj for this function is defaultDigestCryptCodeOfObj.
	
	See also: $(LINK https://en.wikipedia.org/wiki/Crypt_%28C%29)
	+/
	string toCryptString(string delegate(Digest) digestCodeOfObj = toDelegate(&defaultDigestCryptCodeOfObj))
	{
		Appender!string sink;
		toCryptString(sink, digestCodeOfObj);
		return sink.data;
	}

	///ditto
	void toCryptString(Sink)(ref Sink sink,
		string delegate(Digest) digestCodeOfObj = toDelegate(&defaultDigestCryptCodeOfObj))
		if(isOutputRange!(Sink, const(char)))
	{
		sink.put('$');
		sink.put(getDigestCode(digestCodeOfObj, digest));
		sink.put('$');
		Base64.encode(salt, sink);
		sink.put('$');
		Base64.encode(hash, sink);
	}
}

/++
Generates a salted password using any Phobos-compatible digest, default being SHA-512.

(Note: An established "key stretching" algorithm
( $(LINK http://en.wikipedia.org/wiki/Key_stretching#History) ) would be an even
better choice of digest since they provide better protection against
highly-parallelized (ex: GPU) brute-force attacks. But SHA-512, as an SHA-2
algorithm, is still considered cryptographically secure.)

Supports both template-style and OO-style digests. See the documentation of
std.digest.digest for details.

Salt is optional. It will be generated at random if not provided.

Normally, the salt and password are combined as (psuedocode) 'salt~password'.
There is no cryptographic benefit to combining the salt and password any
other way. However, if you need to support an alternate method for
compatibility purposes, you can do so by providing a custom salter delegate.
See the implementation of DAuth's defaultSalter to see how to do this.

If using an OO-style Digest, then digest MUST be non-null. Otherwise,
an UnknownDigestException will be thrown.
+/
Hash!TDigest makeHash(TDigest = DefaultDigest)
	(Password password, Salt salt = randomSalt(), Salter!TDigest salter = toDelegate(&defaultSalter!TDigest))
	if(isDigest!TDigest)
{
	validateStrength!TDigest();
	TDigest digest;
	return makeHashImpl!TDigest(digest, password, salt, salter);
}

///ditto
Hash!TDigest makeHash(TDigest = DefaultDigest)(Password password, Salter!TDigest salter)
	if(isDigest!TDigest)
{
	validateStrength!TDigest();
	TDigest digest;
	return makeHashImpl(digest, password, randomSalt(), salter);
}

///ditto
Hash!Digest makeHash()(Digest digest, Password password, Salt salt = randomSalt(),
	Salter!Digest salter = toDelegate(&defaultSalter!Digest))
{
	enforce(digest, new UnknownDigestException("digest was null, don't know what digest to use"));
	validateStrength(digest);
	return makeHashImpl!Digest(digest, password, salt, salter);
}

///ditto
Hash!Digest makeHash()(Digest digest, Password password, Salter!Digest salter)
{
	enforce(digest, new UnknownDigestException("digest was null, don't know what digest to use"));
	validateStrength(digest);
	return makeHashImpl!Digest(digest, password, randomSalt(), salter);
}

private Hash!TDigest makeHashImpl(TDigest)
	(ref TDigest digest, Password password, Salt salt, Salter!TDigest salter)
	if(isAnyDigest!TDigest)
{
	Hash!TDigest ret;
	ret.digest = digest;
	ret.salt   = salt;
	
	static if(isDigest!TDigest) // template-based digest
		ret.digest.start();
	else
		ret.digest.reset(); // OO-based digest
	
	salter(ret.digest, password, salt);
	ret.hash = ret.digest.finish();
	
	return ret;
}

/// Parses a string that was encoded by Hash.toString.
///
/// Only OO-style digests are used since the digest is specified in the string
/// and therefore only known at runtime.
///
/// Throws ConvException if the string is malformed.
///
/// To support additional digests besides the built-in (Phobos's CRC32, MD5,
/// RIPEMD160 and SHA), supply a custom delegate for digestFromDAuthCode.
/// You can defer to DAuth's defaultDigestFromCode to handle the
/// built-in digests.
///
/// Similarly, to extend crypt(3)-style to support additional digests beyond
/// DAuth's crypt(3) support, supply a custom delegate for digestFromCryptCode.
/// The default implementation is defaultDigestFromCryptCode.
///
/// Example:
/// -------------------
/// import std.digest.digest;
/// import dauth;
/// 
/// struct BBQ42 {...}
/// static assert(isDigest!BBQ42);
/// alias BBQ42Digest = WrapperDigest!BBQ42;
/// 
/// Digest customDigestFromCode(string digestCode)
/// {
///     switch(digestCode)
///     {
///     case "BBQ42": return new BBQ42Digest();
///     case "FAQ17": return new FAQ17Digest();
///     default:
///         return defaultDigestFromCode(digestCode);
///     }
/// }
/// 
/// void doStuff(string hashString)
/// {
///     auto hash = parseHash(hashString, &customDigestFromCode);
/// }
/// -------------------
Hash!Digest parseHash(string str,
	Digest delegate(string) digestFromDAuthCode = toDelegate(&defaultDigestFromCode),
	Digest delegate(string) digestFromCryptCode = toDelegate(&defaultDigestFromCryptCode))
{
	enforceEx!ConvException(!str.empty);
	if(str[0] == '[')
		return parseDAuthHash(str, digestFromDAuthCode);
	else if(str[0] == '$' || str.length == 13)
		return parseCryptHash(str, digestFromCryptCode);
	
	throw new ConvException("Hash string is neither valid DAuth-style nor crypt-style");
}

///ditto
Hash!Digest parseDAuthHash(string str,
	Digest delegate(string) digestFromCode = toDelegate(&defaultDigestFromCode))
{
	// No need to mess with UTF
	auto bytes = cast(immutable(ubyte)[]) str;
	
	// Parse '['
	enforceEx!ConvException(!bytes.empty);
	enforceEx!ConvException(bytes.front == cast(ubyte)'[');
	bytes.popFront();

	// Parse digest code
	auto splitRBracket = bytes.findSplit([']']);
	enforceEx!ConvException( !splitRBracket[0].empty && !splitRBracket[1].empty && !splitRBracket[2].empty );
	auto digestCode = splitRBracket[0];
	bytes = splitRBracket[2];
	
	// Split salt and hash
	auto splitDollar = bytes.findSplit(['$']);
	enforceEx!ConvException( !splitDollar[0].empty && !splitDollar[1].empty && !splitDollar[2].empty );
	auto salt = splitDollar[0];
	auto hash = splitDollar[2];
	
	// Construct Hash
	Hash!Digest result;
	result.salt   = Base64.decode(salt);
	result.hash   = Base64.decode(hash);
	result.digest = digestFromCode(cast(string)digestCode);
	
	return result;
}

///ditto
Hash!Digest parseCryptHash(string str,
	Digest delegate(string) digestFromCode = toDelegate(&defaultDigestFromCryptCode))
{
	// No need to mess with UTF
	auto bytes = cast(immutable(ubyte)[]) str;

	enforceEx!ConvException(!bytes.empty);
	
	// Old crypt-DES style?
	if(bytes[0] != cast(ubyte)'$' && bytes.length == 13)
	{
		auto salt = bytes[0..2];
		auto hash = bytes[2..$];

		// Construct Hash
		Hash!Digest result;
		result.salt   = salt.dup;
		result.hash   = hash.dup;
		result.digest = digestFromCode(null);
		
		return result;
	}
	
	// Parse initial '$'
	enforceEx!ConvException(bytes.front == cast(ubyte)'$');
	bytes.popFront();
	
	// Split digest code, salt and hash
	auto parts = bytes.splitter('$').array();
	enforceEx!ConvException(parts.length == 3);
	auto digestCode = parts[0];
	auto salt       = parts[1];
	auto hash       = parts[2];
	
	// Construct Hash
	Hash!Digest result;
	result.salt   = Base64.decode(salt);
	result.hash   = Base64.decode(hash);
	result.digest = digestFromCode(cast(string)digestCode);
	
	return result;
}

/// Validates a password against an existing salted hash.
///
/// If sHash is a Hash!Digest, then sHash.digest MUST be non-null. Otherwise
/// this function will have no other way to determine what digest to match
/// against, and an UnknownDigestException will be thrown.
bool isPasswordCorrect(TDigest = DefaultDigest)(Password password, Hash!TDigest sHash,
	Salter!TDigest salter = toDelegate(&defaultSalter!TDigest))
	if(isDigest!TDigest)
{
	auto testHash = makeHash!TDigest(password, sHash.salt, salter);
	return lengthConstantEquals(testHash.hash, sHash.hash);
}

///ditto
bool isPasswordCorrect(TDigest = Digest)(Password password, Hash!TDigest sHash,
	Salter!Digest salter = toDelegate(&defaultSalter!Digest))
	if(is(TDigest : Digest))
{
	Hash!Digest testHash;

	if(sHash.digest)
		testHash = makeHash(sHash.digest, password, sHash.salt, salter);
	else
	{
		static if(is(TDigest == Digest))
			throw new UnknownDigestException("Cannot determine digest from a Hash!Digest with a null 'digest' member.");
		else
			testHash = makeHash(new TDigest(), password, sHash.salt, salter);
	}

	return lengthConstantEquals(testHash.hash, sHash.hash);
}

///ditto
bool isPasswordCorrect(TDigest = DefaultDigest)
	(Password password, DigestType!TDigest hash, Salt salt,
		Salter!TDigest salter = toDelegate(&defaultSalter!TDigest))
	if(isDigest!TDigest)
{
	auto testHash = makeHash!TDigest(password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

///ditto
bool isPasswordCorrect()(Password password,
	ubyte[] hash, Salt salt, Digest digest = new DefaultDigestClass(),
	Salter!Digest salter = toDelegate(&defaultSalter!Digest))
{
	auto testHash = makeHash(digest, password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

///ditto
bool isPasswordCorrect()(Password password,
	ubyte[] hash, Salt salt, Salter!Digest salter)
{
	auto testHash = makeHash(new DefaultDigestClass(), password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

version(DAuth_Unittest)
unittest
{
import std.stdio;
writeln(makeHash(dupPassword("pass123")).toString());

char[] input = "...".dup;
Password pass = toPassword(input); // Ref counted with automatic memory zeroing

// Salt is crypto-secure randomized
string hash1 = makeHash(pass).toString(); // Ex: [SHA512]d93Tp...ULle$my7MSJu...NDtd5RG
string hash2 = makeHash(pass).toCryptString(); // Ex: $6$d93Tp...ULle$my7MSJu...NDtd5RG

bool ok = isPasswordCorrect(pass, parseHash(hash1));

	// For validity of sanity checks, these sha/md5 and base64 strings
	// were NOT generated using Phobos.
	auto plainText1        = dupPassword("hello world");
	enum md5Hash1          = cast(ubyte[16]) x"5eb63bbbe01eeed093cb22bb8f5acdc3";
	enum md5Hash1Base64    = "XrY7u+Ae7tCTyyK7j1rNww==";
	enum sha1Hash1         = cast(ubyte[20]) x"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
	enum sha1Hash1Base64   = "Kq5sNclPz7QV2+lfQIuc6R7oRu0=";
	enum sha512Hash1       = cast(ubyte[64]) x"309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
	enum sha512Hash1Base64 = "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==";

	auto plainText2        = dupPassword("some salt");
	enum md5Hash2          = cast(ubyte[16]) x"befbc24b5c6a74591c0d8e6397b8a398";
	enum md5Hash2Base64    = "vvvCS1xqdFkcDY5jl7ijmA==";
	enum sha1Hash2         = cast(ubyte[20]) x"78bc8b0e186b0aa698f12dc27736b492e4dacfc8";
	enum sha1Hash2Base64   = "eLyLDhhrCqaY8S3Cdza0kuTaz8g=";
	enum sha512Hash2       = cast(ubyte[64]) x"637246608760dc79f00d3ad4fd26c246bb217e10f811cdbf6fe602c3981e98b8cadacadc452808ae393ac46e8a7e967aa99711d7fd7ed6c055264787f8043693";
	enum sha512Hash2Base64 = "Y3JGYIdg3HnwDTrU/SbCRrshfhD4Ec2/b+YCw5gemLjK2srcRSgIrjk6xG6KfpZ6qZcR1/1+1sBVJkeH+AQ2kw==";
	
	unitlog("Sanity checking unittest's data");
	assert(md5Of(plainText1.data) == md5Hash1);
	assert(md5Of(plainText2.data) == md5Hash2);
	assert(sha1Of(plainText1.data) == sha1Hash1);
	assert(sha1Of(plainText2.data) == sha1Hash2);
	assert(sha512Of(plainText1.data) == sha512Hash1);
	assert(sha512Of(plainText2.data) == sha512Hash2);
	assert(Base64.encode(md5Hash1) == md5Hash1Base64);
	assert(Base64.encode(md5Hash2) == md5Hash2Base64);
	assert(Base64.encode(sha1Hash1) == sha1Hash1Base64);
	assert(Base64.encode(sha1Hash2) == sha1Hash2Base64);
	assert(Base64.encode(sha512Hash1) == sha512Hash1Base64);
	assert(Base64.encode(sha512Hash2) == sha512Hash2Base64);

	unitlog("Testing Hash.toString");
	Hash!SHA1 result1;
	result1.hash = cast(AnyDigestType!SHA1) sha1Hash1;
	result1.salt = cast(Salt)               sha1Hash2;
	assert( result1.toString() == text("[SHA1]", sha1Hash2Base64, "$", sha1Hash1Base64) );

	Hash!MD5 result1_md5;
	result1_md5.hash = cast(AnyDigestType!MD5) md5Hash1;
	result1_md5.salt = cast(Salt)              md5Hash2;
	assert( result1_md5.toString() == text("[MD5]", md5Hash2Base64, "$", md5Hash1Base64) );

	Hash!SHA512 result1_512;
	result1_512.hash = cast(AnyDigestType!SHA512) sha512Hash1;
	result1_512.salt = cast(Salt)                 sha512Hash2;
	assert( result1_512.toString() == text("[SHA512]", sha512Hash2Base64, "$", sha512Hash1Base64) );
	
	unitlog("Testing Hash.toString - crypt(3)");
	assertThrown!UnknownDigestException( result1.toCryptString() );
	assert( result1_md5.toCryptString() == text("$1$", md5Hash2Base64,    "$", md5Hash1Base64) );
	assert( result1_512.toCryptString() == text("$6$", sha512Hash2Base64, "$", sha512Hash1Base64) );

	unitlog("Testing makeHash([digest,] pass, salt [, salter])");
	void altSalter(TDigest)(ref TDigest digest, Password password, Salt salt)
	{
		// Reverse order
		digest.put(password.data);
		digest.put(cast(immutable(ubyte)[])salt);
	}
	
	auto result2          = makeHash!SHA1(plainText1, cast(Salt)sha1Hash2[]);
	auto result2AltSalter = makeHash!SHA1(plainText1, cast(Salt)sha1Hash2[], &altSalter!SHA1);
	auto result3          = makeHash(new SHA1Digest(), plainText1, cast(Salt)sha1Hash2[]);
	auto result3AltSalter = makeHash(new SHA1Digest(), plainText1, cast(Salt)sha1Hash2[], &altSalter!Digest);

	assert(result2.salt       == result3.salt);
	assert(result2.hash       == result3.hash);
	assert(result2.toString() == result3.toString());
	assert(result2.toString() == makeHash!SHA1(plainText1, cast(Salt)sha1Hash2[]).toString());
	assert(result2.salt == result1.salt);

	assert(result2AltSalter.salt       == result3AltSalter.salt);
	assert(result2AltSalter.hash       == result3AltSalter.hash);
	assert(result2AltSalter.toString() == result3AltSalter.toString());
	assert(result2AltSalter.toString() == makeHash!SHA1(plainText1, cast(Salt)sha1Hash2[], &altSalter!SHA1).toString());
	
	assert(result2.salt       == result2AltSalter.salt);
	assert(result2.hash       != result2AltSalter.hash);
	assert(result2.toString() != result2AltSalter.toString());

	auto result2_512          = makeHash!SHA512(plainText1, cast(Salt)sha512Hash2[]);
	auto result2_512AltSalter = makeHash!SHA512(plainText1, cast(Salt)sha512Hash2[], &altSalter!SHA512);
	auto result3_512          = makeHash(new SHA512Digest(), plainText1, cast(Salt)sha512Hash2[]);
	auto result3_512AltSalter = makeHash(new SHA512Digest(), plainText1, cast(Salt)sha512Hash2[], &altSalter!Digest);

	assert(result2_512.salt       == result3_512.salt);
	assert(result2_512.hash       == result3_512.hash);
	assert(result2_512.toString() == result3_512.toString());
	assert(result2_512.toString() == makeHash!SHA512(plainText1, cast(Salt)sha512Hash2[]).toString());
	assert(result2_512.salt == result1_512.salt);

	assert(result2_512AltSalter.salt       == result3_512AltSalter.salt);
	assert(result2_512AltSalter.hash       == result3_512AltSalter.hash);
	assert(result2_512AltSalter.toString() == result3_512AltSalter.toString());
	assert(result2_512AltSalter.toString() == makeHash!SHA512(plainText1, cast(Salt)sha512Hash2[], &altSalter!SHA512).toString());
	
	assert(result2_512.salt       == result2_512AltSalter.salt);
	assert(result2_512.hash       != result2_512AltSalter.hash);
	assert(result2_512.toString() != result2_512AltSalter.toString());
	
	assertThrown!UnknownDigestException( makeHash(cast(SHA1Digest)null, plainText1, cast(Salt)sha1Hash2[]) );
	assertThrown!UnknownDigestException( makeHash(cast(Digest)null,     plainText1, cast(Salt)sha1Hash2[]) );

	unitlog("Testing makeHash(pass)");
	import dauth.random : randomPassword;
	auto resultRand1 = makeHash!SHA1(randomPassword());
	auto resultRand2 = makeHash!SHA1(randomPassword());

	assert(resultRand1.salt != result1.salt);

	assert(resultRand1.salt != resultRand2.salt);
	assert(resultRand1.hash != resultRand2.hash);

	unitlog("Testing parseHash()");
	auto result2Parsed = parseDAuthHash( result2_512.toString() );
	assert(result2_512.salt       == result2Parsed.salt);
	assert(result2_512.hash       == result2Parsed.hash);
	assert(result2_512.toString() == result2Parsed.toString());

	assert(makeHash(result2Parsed.digest, plainText1, result2Parsed.salt) == result2Parsed);
	assertThrown!ConvException(parseDAuthHash( result2_512.toCryptString() ));
	assert(parseHash( result2_512.toString() ).salt            == parseDAuthHash( result2_512.toString() ).salt);
	assert(parseHash( result2_512.toString() ).hash            == parseDAuthHash( result2_512.toString() ).hash);
	assert(parseHash( result2_512.toString() ).toString()      == parseDAuthHash( result2_512.toString() ).toString());
	assert(parseHash( result2_512.toString() ).toCryptString() == parseDAuthHash( result2_512.toString() ).toCryptString());
	
	unitlog("Testing parseHash() - crypt(3)");
	auto result2ParsedCrypt = parseCryptHash( result2_512.toCryptString() );
	assert(result2_512.salt       == result2ParsedCrypt.salt);
	assert(result2_512.hash       == result2ParsedCrypt.hash);
	assert(result2_512.toString() == result2ParsedCrypt.toString());

	assert(makeHash(result2ParsedCrypt.digest, plainText1, result2ParsedCrypt.salt) == result2ParsedCrypt);
	assertThrown!ConvException(parseCryptHash( result2_512.toString() ));
	assert(parseHash( result2_512.toCryptString() ).salt            == parseCryptHash( result2_512.toCryptString() ).salt);
	assert(parseHash( result2_512.toCryptString() ).hash            == parseCryptHash( result2_512.toCryptString() ).hash);
	assert(parseHash( result2_512.toCryptString() ).toString()      == parseCryptHash( result2_512.toCryptString() ).toString());
	assert(parseHash( result2_512.toCryptString() ).toCryptString() == parseCryptHash( result2_512.toCryptString() ).toCryptString());
	
	auto desCryptHash = "sa5JEXtYx/rm6";
	assertThrown!UnknownDigestException( parseHash(desCryptHash) );
	assert(collectExceptionMsg( parseHash(desCryptHash) ).canFind("DES"));

	unitlog("Testing isPasswordCorrect");
	assert(isPasswordCorrect     (plainText1, result2));
	assert(isPasswordCorrect!SHA1(plainText1, result2.hash, result2.salt));
	assert(isPasswordCorrect     (plainText1, result2.hash, result2.salt, new SHA1Digest()));

	assert(isPasswordCorrect!SHA1(plainText1, result2AltSalter, &altSalter!SHA1));
	assert(isPasswordCorrect!SHA1(plainText1, result2AltSalter.hash, result2AltSalter.salt, &altSalter!SHA1));
	assert(isPasswordCorrect     (plainText1, result2AltSalter.hash, result2AltSalter.salt, new SHA1Digest(), &altSalter!Digest));

	assert(!isPasswordCorrect     (dupPassword("bad pass"), result2));
	assert(!isPasswordCorrect!SHA1(dupPassword("bad pass"), result2.hash, result2.salt));
	assert(!isPasswordCorrect     (dupPassword("bad pass"), result2.hash, result2.salt, new SHA1Digest()));

	assert(!isPasswordCorrect!SHA1(dupPassword("bad pass"), result2AltSalter, &altSalter!SHA1));
	assert(!isPasswordCorrect!SHA1(dupPassword("bad pass"), result2AltSalter.hash, result2AltSalter.salt, &altSalter!SHA1));
	assert(!isPasswordCorrect     (dupPassword("bad pass"), result2AltSalter.hash, result2AltSalter.salt, new SHA1Digest(), &altSalter!Digest));
	
	Hash!SHA1Digest ooHashSHA1Digest;
	ooHashSHA1Digest.salt = result2.salt;
	ooHashSHA1Digest.hash = result2.hash;
	ooHashSHA1Digest.digest = new SHA1Digest();
	assert( isPasswordCorrect(plainText1, ooHashSHA1Digest) );
	ooHashSHA1Digest.digest = null;
	assert( isPasswordCorrect(plainText1, ooHashSHA1Digest) );
	
	Hash!Digest ooHashDigest;
	ooHashDigest.salt = result2.salt;
	ooHashDigest.hash = result2.hash;
	ooHashDigest.digest = new SHA1Digest();
	assert( isPasswordCorrect(plainText1, ooHashDigest) );
	ooHashDigest.digest = null;
	assertThrown!UnknownDigestException( isPasswordCorrect(plainText1, ooHashDigest) );
	
	assert( isPasswordCorrect(plainText1, parseHash(result2.toString())) );

	auto wrongSalt = result2;
	wrongSalt.salt = wrongSalt.salt[4..$-1];
	
	assert(!isPasswordCorrect     (plainText1, wrongSalt));
	assert(!isPasswordCorrect!SHA1(plainText1, wrongSalt.hash, wrongSalt.salt));
	assert(!isPasswordCorrect     (plainText1, wrongSalt.hash, wrongSalt.salt, new SHA1Digest()));

	Hash!MD5 wrongDigest;
	wrongDigest.salt = result2.salt;
	wrongDigest.hash = cast(ubyte[16])result2.hash[0..16];
	
	assert(!isPasswordCorrect    (plainText1, wrongDigest));
	assert(!isPasswordCorrect!MD5(plainText1, wrongDigest.hash, wrongDigest.salt));
	assert(!isPasswordCorrect    (plainText1, wrongDigest.hash, wrongDigest.salt, new MD5Digest()));
}

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

// Borrowed from Phobos (TemplateArgsOf only exists in DMD 2.066 and up).
package template DAuth_TemplateArgsOf(alias T : Base!Args, alias Base, Args...)
{
	alias DAuth_TemplateArgsOf = Args;
}
package template DAuth_TemplateArgsOf(T : Base!Args, alias Base, Args...)
{
	alias DAuth_TemplateArgsOf = Args;
}
static assert(is( DAuth_TemplateArgsOf!( Hash!SHA1   )[0] == SHA1   ));
static assert(is( DAuth_TemplateArgsOf!( Hash!Digest )[0] == Digest ));

private struct dummy(T) {}
static if(!is(std.traits.TemplateArgsOf!(dummy!int)))
	private alias TemplateArgsOf = DAuth_TemplateArgsOf;
