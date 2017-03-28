module instauser.basic.hash;

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

/// Tests if the type is an instance of struct Hash(some digest)
template isHash(T)
{
	enum isHash = is( Hash!(TemplateArgsOf!(T)[0]) == T );
}

version(InstaUserBasic_Unittest)
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

/++
Contains all the relevant information for a salted hash.
Note the digest type can be obtained via DigestOf!(SomeHashType).
+/
struct Hash(TDigest) if(isAnyDigest!TDigest)
{
	Salt salt; /// The salt that was used.
	
	/++
	The hash of the salted password. To obtain a printable DB-friendly
	string, pass this to std.digest.digest.toHexString.
	+/
	AnyDigestType!TDigest hash;
	
	/// The digest that was used for hashing.
	TDigest digest;
	
	/++
	Encodes the digest, salt and hash into a convenient forward-compatible
	string format, ready for insertion into a database.
	
	To support additional digests besides the built-in (Phobos's CRC32, MD5,
	RIPEMD160 and SHA), supply a custom delegate for digestCodeOfObj.
	Your custom digestCodeOfObj only needs to handle OO-style digests.
	As long as the OO-style digests were created using Phobos's
	WrapperDigest template, the template-style version will be handled
	automatically. You can defer to InstaUser-Basic's defaultDigestCodeOfObj to
	handle the built-in digests.
	
	Example:
	-------------------
	import std.digest.digest;
	import instauser.basic;
	
	struct BBQ42 {...}
	static assert(isDigest!BBQ42);
	alias BBQ42Digest = WrapperDigest!BBQ42;
	
	string customDigestCodeOfObj(Digest digest)
	{
	    if     (cast(BBQ42Digest)digest) return "BBQ42";
	    else if(cast(FAQ17Digest)digest) return "FAQ17";
	    else
	        return defaultDigestCodeOfObj(digest);
	}
	
	void doStuff(Hash!BBQ42 hash)
	{
	    writeln( hash.toString(&customDigestCodeOfObj) );
	}
	-------------------
	
	Optional_Params:
	digestCodeOfObj - Default value is 'toDelegate(&defaultDigestCodeOfObj)'
	+/
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
	Just like toString, but instead of standard InstaUser-style format, the
	output string is in the crypt(3)-style format.
	
	The crypt(3) format does not support all hash types, and InstaUser-Basic
	doesn't necessarily support all possible forms of crypt(3) hashes (although
	it does strive to support as many as possible).
	
	InstaUser-Basic currently supports crypt(3)-style format for MD5, SHA256
	and SHA512 hashes. Other hashes (unless manually handled by a custom
	digestCodeOfObj) will cause an UnknownDigestException to be thrown.
	
	The default digestCodeOfObj for this function is defaultDigestCryptCodeOfObj.
	
	Optional_Params:
	digestCodeOfObj - Default value is 'toDelegate(&defaultDigestCryptCodeOfObj)'

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
See the implementation of InstaUser-Basic's defaultSalter to see how to do this.

If using an OO-style Digest, then digest MUST be non-null. Otherwise,
an UnknownDigestException will be thrown.

Optional_Params:
salt - Default value is 'randomSalt()'

salter - Default value is 'toDelegate(&defaultSalter!TDigest)'
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

/++
Parses a string that was encoded by Hash.toString.

Only OO-style digests are used since the digest is specified in the string
and therefore only known at runtime.

Throws ConvException if the string is malformed.

To support additional digests besides the built-in (Phobos's CRC32, MD5,
RIPEMD160 and SHA), supply a custom delegate for digestFromInstaUserCode.
You can defer to InstaUser-Basic's defaultDigestFromCode to handle the
built-in digests.

Similarly, to extend crypt(3)-style to support additional digests beyond
InstaUser-Basic's crypt(3) support, supply a custom delegate for digestFromCryptCode.
The default implementation is defaultDigestFromCryptCode.

Example:
-------------------
import std.digest.digest;
import instauser.basic;

struct BBQ42 {...}
static assert(isDigest!BBQ42);
alias BBQ42Digest = WrapperDigest!BBQ42;

Digest customDigestFromCode(string digestCode)
{
    switch(digestCode)
    {
    case "BBQ42": return new BBQ42Digest();
    case "FAQ17": return new FAQ17Digest();
    default:
        return defaultDigestFromCode(digestCode);
    }
}

void doStuff(string hashString)
{
    auto hash = parseHash(hashString, &customDigestFromCode);
}
-------------------

Optional_Params:
digestFromInstaUserCode - Default value is 'toDelegate(&defaultDigestFromCode)'

digestFromCryptCode - Default value is 'toDelegate(&defaultDigestFromCryptCode)'
+/
Hash!Digest parseHash(string str,
	Digest delegate(string) digestFromInstaUserCode = toDelegate(&defaultDigestFromCode),
	Digest delegate(string) digestFromCryptCode = toDelegate(&defaultDigestFromCryptCode))
{
	enforceEx!ConvException(!str.empty);
	if(str[0] == '[')
		return parseInstaUserHash(str, digestFromInstaUserCode);
	else if(str[0] == '$' || str.length == 13)
		return parseCryptHash(str, digestFromCryptCode);
	
	throw new ConvException("Hash string is neither valid InstaUser-style nor crypt-style");
}

///ditto
Hash!Digest parseInstaUserHash(string str,
	Digest delegate(string) digestFromInstaUserCode = toDelegate(&defaultDigestFromCode))
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
	result.digest = digestFromInstaUserCode(cast(string)digestCode);
	
	return result;
}

///ditto
Hash!Digest parseCryptHash(string str,
	Digest delegate(string) digestFromCryptCode = toDelegate(&defaultDigestFromCryptCode))
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
		result.digest = digestFromCryptCode(null);
		
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
	result.digest = digestFromCryptCode(cast(string)digestCode);
	
	return result;
}

/++
Validates a password against an existing salted hash.

If sHash is a Hash!Digest, then sHash.digest MUST be non-null. Otherwise
this function will have no other way to determine what digest to match
against, and an UnknownDigestException will be thrown.

Optional_Params:
salter - Default value is 'toDelegate(&defaultSalter!TDigest)'

digest - Default value is 'new DefaultDigestClass()'
+/
bool isSameHash(TDigest = DefaultDigest)(Password password, Hash!TDigest sHash,
	Salter!TDigest salter = toDelegate(&defaultSalter!TDigest))
	if(isDigest!TDigest)
{
	auto testHash = makeHash!TDigest(password, sHash.salt, salter);
	return lengthConstantEquals(testHash.hash, sHash.hash);
}

///ditto
bool isSameHash(TDigest = Digest)(Password password, Hash!TDigest sHash,
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
bool isSameHash(TDigest = DefaultDigest)
	(Password password, DigestType!TDigest hash, Salt salt,
		Salter!TDigest salter = toDelegate(&defaultSalter!TDigest))
	if(isDigest!TDigest)
{
	auto testHash = makeHash!TDigest(password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

///ditto
bool isSameHash()(Password password,
	ubyte[] hash, Salt salt, Digest digest = new DefaultDigestClass(),
	Salter!Digest salter = toDelegate(&defaultSalter!Digest))
{
	auto testHash = makeHash(digest, password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

///ditto
bool isSameHash()(Password password,
	ubyte[] hash, Salt salt, Salter!Digest salter)
{
	auto testHash = makeHash(new DefaultDigestClass(), password, salt, salter);
	return lengthConstantEquals(testHash.hash, hash);
}

/++
Alias for backwards compatibility.

isPasswordCorrect will become deprecated in a future version. Use isSameHash instead.
+/
alias isPasswordCorrect = isSameHash;
