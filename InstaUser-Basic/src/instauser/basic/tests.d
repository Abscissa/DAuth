module instauser.basic.tests;

import std.algorithm;
import std.base64;
import std.conv;
import std.digest.crc;
import std.digest.md;
import std.digest.ripemd;
import std.digest.sha;
import std.exception;

import instauser.basic.digest;
import instauser.basic.exceptions;
import instauser.basic.hash;
import instauser.basic.password;
import instauser.basic.salt;

version(InstaUserBasic_Unittest)
{
	version(InstaUserBasic_Unittest_Quiet) {} else
		version = Loud_Unittest;
	
	version(Loud_Unittest)
		import std.stdio;
	
	void unitlog(string str)
	{
		version(Loud_Unittest)
		{
			writeln("unittest InstaUser-Basic: ", str);
			stdout.flush();
		}
	}
}

version(InstaUserBasic_Unittest)
unittest
{
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
	import instauser.basic.random : randomPassword;
	auto resultRand1 = makeHash!SHA1(randomPassword());
	auto resultRand2 = makeHash!SHA1(randomPassword());

	assert(resultRand1.salt != result1.salt);

	assert(resultRand1.salt != resultRand2.salt);
	assert(resultRand1.hash != resultRand2.hash);

	unitlog("Testing parseHash()");
	auto result2Parsed = parseInstaUserHash( result2_512.toString() );
	assert(result2_512.salt       == result2Parsed.salt);
	assert(result2_512.hash       == result2Parsed.hash);
	assert(result2_512.toString() == result2Parsed.toString());

	assert(makeHash(result2Parsed.digest, plainText1, result2Parsed.salt) == result2Parsed);
	assertThrown!ConvException(parseInstaUserHash( result2_512.toCryptString() ));
	assert(parseHash( result2_512.toString() ).salt            == parseInstaUserHash( result2_512.toString() ).salt);
	assert(parseHash( result2_512.toString() ).hash            == parseInstaUserHash( result2_512.toString() ).hash);
	assert(parseHash( result2_512.toString() ).toString()      == parseInstaUserHash( result2_512.toString() ).toString());
	assert(parseHash( result2_512.toString() ).toCryptString() == parseInstaUserHash( result2_512.toString() ).toCryptString());
	
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

	unitlog("Testing isSameHash");
	assert(isSameHash     (plainText1, result2));
	assert(isSameHash!SHA1(plainText1, result2.hash, result2.salt));
	assert(isSameHash     (plainText1, result2.hash, result2.salt, new SHA1Digest()));

	assert(isSameHash!SHA1(plainText1, result2AltSalter, &altSalter!SHA1));
	assert(isSameHash!SHA1(plainText1, result2AltSalter.hash, result2AltSalter.salt, &altSalter!SHA1));
	assert(isSameHash     (plainText1, result2AltSalter.hash, result2AltSalter.salt, new SHA1Digest(), &altSalter!Digest));

	assert(!isSameHash     (dupPassword("bad pass"), result2));
	assert(!isSameHash!SHA1(dupPassword("bad pass"), result2.hash, result2.salt));
	assert(!isSameHash     (dupPassword("bad pass"), result2.hash, result2.salt, new SHA1Digest()));

	assert(!isSameHash!SHA1(dupPassword("bad pass"), result2AltSalter, &altSalter!SHA1));
	assert(!isSameHash!SHA1(dupPassword("bad pass"), result2AltSalter.hash, result2AltSalter.salt, &altSalter!SHA1));
	assert(!isSameHash     (dupPassword("bad pass"), result2AltSalter.hash, result2AltSalter.salt, new SHA1Digest(), &altSalter!Digest));
	
	Hash!SHA1Digest ooHashSHA1Digest;
	ooHashSHA1Digest.salt = result2.salt;
	ooHashSHA1Digest.hash = result2.hash;
	ooHashSHA1Digest.digest = new SHA1Digest();
	assert( isSameHash(plainText1, ooHashSHA1Digest) );
	ooHashSHA1Digest.digest = null;
	assert( isSameHash(plainText1, ooHashSHA1Digest) );
	
	Hash!Digest ooHashDigest;
	ooHashDigest.salt = result2.salt;
	ooHashDigest.hash = result2.hash;
	ooHashDigest.digest = new SHA1Digest();
	assert( isSameHash(plainText1, ooHashDigest) );
	ooHashDigest.digest = null;
	assertThrown!UnknownDigestException( isSameHash(plainText1, ooHashDigest) );
	
	assert( isSameHash(plainText1, parseHash(result2.toString())) );

	auto wrongSalt = result2;
	wrongSalt.salt = wrongSalt.salt[4..$-1];
	
	assert(!isSameHash     (plainText1, wrongSalt));
	assert(!isSameHash!SHA1(plainText1, wrongSalt.hash, wrongSalt.salt));
	assert(!isSameHash     (plainText1, wrongSalt.hash, wrongSalt.salt, new SHA1Digest()));

	Hash!MD5 wrongDigest;
	wrongDigest.salt = result2.salt;
	wrongDigest.hash = cast(ubyte[16])result2.hash[0..16];
	
	assert(!isSameHash    (plainText1, wrongDigest));
	assert(!isSameHash!MD5(plainText1, wrongDigest.hash, wrongDigest.salt));
	assert(!isSameHash    (plainText1, wrongDigest.hash, wrongDigest.salt, new MD5Digest()));
}
