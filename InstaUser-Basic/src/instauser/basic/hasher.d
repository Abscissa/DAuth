module instauser.basic.hasher;

import std.digest.crc : Digest;
import std.traits;

//TODO: Get rid of these two dependencies
import instauser.basic.digest;
import instauser.basic.bcrypt;

interface Hasher
{
	ubyte[] hash(Password, Salt);
}

/+
//TODO: Is this approach possible with std.variant? Maybe a third-party variant?
struct Hasher
{
	import std.variant;
	Variant variant; /// Underlying `Variant`
	alias variant this;

	this(H)(H hasher) if(isHasher!H)
	{
		variant = hasher;
	}

	ubyte[] hasher(Password pass, Salt salt);
	{
		//TODO: How to do this????
	}
}
+/

enum isHasher(T) = is(typeof(
	() {
		T hasher = T.init;
		ubyte[] hash = hasher.hash(Password(), Salt());
	}
));

template hasStaticHashLength(H) if(isHasher!H)
{
	enum hasStaticHashLength = is(typeof(
		() {
			size_t len = H.hashLength;
		}
	));
}

template RawHashType(H) if(isHasher!H)
{
	alias RawHashType = ReturnType!(H.hash);
}

/++
Default implementation of 'digestCodeOfObj' for InstaUser-style hash strings.
See 'Hash!(TDigest).toString' for more info.
+/
string defaultHasherCodeOfObj(Hasher hasher)
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
		throw new UnknownDigestException("Unknown hasher type");
}

/++
Default implementation of 'digestFromCode' for InstaUser-style hash strings.
See 'parseHash' for more info.
+/
//TODO; Should this return an OO-style version of Hasher, ie a `Hasher`?
Hasher defaultHasherFromCode(string hasherCode)
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
		throw new UnknownDigestException("Unknown hasher code");
	}
}

/++
Default implementation of 'digestCodeOfObj' for Unix crypt-style hash strings.
See 'Hash!(TDigest).toString' for more info.
+/
string defaultHasherCryptCodeOfObj(Hasher hasher)
{
	if     (cast( MD5Digest    )digest) return "1";
	else if(cast( SHA256Digest )digest) return "5";
	else if(cast( SHA512Digest )digest) return "6";
	else
		throw new UnknownDigestException("Unknown hasher type");
}

/++
Default implementation of 'digestFromCode' for Unix crypt-style hash strings.
See 'parseHash' for more info.
+/
//TODO; Should this return an OO-style version of Hasher, ie a `Hasher`?
Hasher defaultHasherFromCryptCode(string hasherCode)
{
	switch(digestCode)
	{
	case "":   throw new UnknownDigestException(`Old crypt-DES not currently supported`);
	case "1":  return new MD5Digest();
	case "5":  return new SHA256Digest();
	case "6":  return new SHA512Digest();
	default:
		throw new UnknownDigestException("Unknown hasher code");
	}
}
