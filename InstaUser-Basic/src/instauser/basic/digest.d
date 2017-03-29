module instauser.basic.digest;

import std.digest.crc;
import std.digest.md;
import std.digest.ripemd;
import std.digest.sha;
import std.traits;

import instauser.basic.exceptions;
import instauser.basic.hash;

alias DefaultDigest = SHA512; /// Default is SHA-512
alias DefaultDigestClass = WrapperDigest!DefaultDigest; /// OO-style version of 'DefaultDigest'.

/++
Default implementation of 'digestCodeOfObj' for InstaUser-style hash strings.
See 'Hash!(TDigest).toString' for more info.
+/
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

/++
Default implementation of 'digestFromCode' for InstaUser-style hash strings.
See 'parseHash' for more info.
+/
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

/++
Default implementation of 'digestCodeOfObj' for Unix crypt-style hash strings.
See 'Hash!(TDigest).toString' for more info.
+/
string defaultDigestCryptCodeOfObj(Digest digest)
{
	if     (cast( MD5Digest    )digest) return "1";
	else if(cast( SHA256Digest )digest) return "5";
	else if(cast( SHA512Digest )digest) return "6";
	else
		throw new UnknownDigestException("Unknown digest type");
}

/++
Default implementation of 'digestFromCode' for Unix crypt-style hash strings.
See 'parseHash' for more info.
+/
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

/++
Like std.digest.digest.isDigest, but also accepts OO-style digests
(ie. classes deriving from interface std.digest.digest.Digest)
+/
template isAnyDigest(TDigest)
{
	enum isAnyDigest =
		isDigest!TDigest ||
		is(TDigest : Digest);
}

version(InstaUserBasic_Unittest)
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

/++
Like std.digest.digest.DigestType, but also accepts OO-style digests
(ie. classes deriving from interface std.digest.digest.Digest)
+/
template AnyDigestType(TDigest)
{
	static assert(isAnyDigest!TDigest,
		TDigest.stringof ~ " is not a template-style or OO-style digest (fails isAnyDigest!T)");
	
	static if(isDigest!TDigest)
		alias AnyDigestType = DigestType!TDigest;
	else
		alias AnyDigestType = ubyte[];
}

version(InstaUserBasic_Unittest)
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

/// Retreive the digest type of a struct Hash(some digest)
template DigestOf(T) if(isHash!T)
{
	alias DigestOf = TemplateArgsOf!(T)[0];
}

version(InstaUserBasic_Unittest)
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
