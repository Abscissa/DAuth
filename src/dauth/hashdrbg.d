/++
DAuth - Authentication Utility for D
Hash_DRBG Cryptographic Random Number Generator

Main module: $(LINK2 index.html,dauth)$(BR)
+/

module dauth.hashdrbg;

import std.conv;
import std.exception;
import std.random;
import std.range;
import std.stdio;
import std.traits;
import std.typecons;

import dauth.core;
import dauth.sha;

version(Windows)
{
	import std.c.windows.windows;
	import core.runtime;
}

///
enum isRandomStream(T) =
	is(typeof({
		static assert(T.isUniformRandomStream);
		T t;
		ubyte[] buf;
		t.read(buf);
	}));

static assert(isRandomStream!(SystemEntropyStream));
static assert(isRandomStream!(HashDRBGStream!()));
static assert(!isRandomStream!(SystemEntropy!uint));
static assert(!isRandomStream!(HashDRBG!uint));
static assert(!isRandomStream!uint);
static assert(!isRandomStream!File);

/++
Reads any desired amount of random entropy from a system-specific cryptographic
random number generator. On Windows, this loads ADVAPI32.DLL and uses
RtlGenRandom. On Posix, this uses '/dev/random'.

Optionally, you can use open() and close() to control the lifetime of
SystemEntropyStream's system handles (ie, loading/uloading ADVAPI32.DLL and
opening/closing '/dev/random'). But this is not normally necessary since
SystemEntropyStream automatically opens them upon reading and closes upon
module destruction.

The speed and cryptographic security of this is dependent on your operating
system. This may be perfectly suitable for many cryptographic-grade random
number generation needs, but it's primary inteded for seeding/reseeding
cryptographic psuedo-random number generators, such as Hash_DRBG or HMAC_DRBG,
which are likely to be faster and no less secure than using an entropy source
directly.
+/
struct SystemEntropyStream
{
	enum isUniformRandomStream = true; /// Mark this as a Rng Stream

	version(Windows)
	{
		private static HMODULE _advapi32;
		private static extern(Windows) BOOL function(void*, uint) _RtlGenRandom;
	}
	else version(Posix)
		private static File devRandom;
	else
		static assert(false);
	 
	/// Fills the buffer with entropy from the system-specific entropy generator.
	/// Automatically opens SystemEntropyStream if it's closed.
	static void read(ubyte[] buf)
	{
		open();
		
		version(Windows)
		{
			enforce(buf.length < uint.max, "Cannot read more than uint.max bytes from RtlGenRandom");
			_RtlGenRandom(buf.ptr, cast(uint)buf.length);
		}
		else version(Posix)
			devRandom.rawRead(buf);
		else
			static assert(false);
	}

	/// Establishes a handle/connection to the system-specific entropy generator.
	/// Does nothing if already open.
	static void open()
	{
		if(isOpen)
			return;
		
		version(Windows)
		{
			// Reference: http://blogs.msdn.com/b/michael_howard/archive/2005/01/14/353379.aspx
			_advapi32 = Runtime.loadLibrary("ADVAPI32.DLL");
			_RtlGenRandom = cast(typeof(_RtlGenRandom))_advapi32.GetProcAddress("SystemFunction036");
			enforce(_RtlGenRandom);
		}
		else version(Posix)
		{
			devRandom = File("/dev/random");
			devRandom.setvbuf(null, _IONBF); // Disable buffering for security
		}
		else
			static assert(false);
	}
	
	///	Manually release the handle/connection to the system-specific entropy generator.
	static void close()
	{
		version(Windows)
		{
			if(_advapi32)
			{
				Runtime.unloadLibrary(_advapi32);
				_advapi32 = null;
				_RtlGenRandom = null;
			}
		}
		else version(Posix)
		{
			if(devRandom.isOpen)
				devRandom.close();
		}
		else
			static assert(false);
	}

	/// Check whether SystemEntropyStream is currently connected to with the
	/// system-specific entropy generator.
	static @property bool isOpen()
	{
		version(Windows)
			return _advapi32 && _RtlGenRandom;
		else version(Posix)
			return devRandom.isOpen;
		else
			static assert(false);
	}
	
	/// Automatically close upon module destruction.
	static ~this()
	{
		close();
	}
}

/// A convenience alias to create a UniformRNG from SystemEntropyStream.
/// See the WrappedStreamRNG documentation for important information.
alias SystemEntropy(Elem) = WrappedStreamRNG!(SystemEntropyStream, Elem);

static assert(isUniformRNG!(SystemEntropy!(ubyte[1]), ubyte[1]));
static assert(isUniformRNG!(SystemEntropy!(ubyte[5]), ubyte[5]));
static assert(isUniformRNG!(SystemEntropy!ubyte,      ubyte   ));
static assert(isUniformRNG!(SystemEntropy!ushort,     ushort  ));
static assert(isUniformRNG!(SystemEntropy!uint,       uint    ));
static assert(isUniformRNG!(SystemEntropy!ulong,      ulong   ));

/++
Cryptographic random number generator Hash_DRBG, as defined in
NIST's $(LINK2 http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf, SP800-90A).

TSHA: Any SHA-1 or SHA-2 digest type. Default is SHA512.

custom: Hash_DRBG's personalization string. You can optionally set this to any
specific value of your own choosing for improved security.
+/
struct HashDRBGStream(TSHA = SHA512, string custom = "D Crypto RNG")
	if(isInstanceOf!(SHA, TSHA))
{
	enum isUniformRandomStream = true; /// Mark this as a Rng Stream

	// In bits. This is the same as the SHA's digestSize
	private enum outputSizeBits = TemplateArgsOf!(TSHA)[1];

	static if(outputSizeBits < 384)
		private enum seedSizeBytes = 440/8; // In bytes
	else
		private enum seedSizeBytes = 888/8; // In bytes
	
	// This can be just about any arbitrary size, although there is a
	// minimum. 1024 bits is above the minimum for SHA-1 and all SHA-2.
	// See NIST's [SP800-90A] and [SP800-57] for details.
	private enum entropySizeBytes = 1024/8;
	
	// This must be at least entropySizeBytes/2
	private enum nonceSizeBytes = entropySizeBytes/2;
	
	// value[1..$] is Hash_DRBG's secret working state value V
	// value[0] is a scratchpad to avoid unnecessary copying/concating of V
	private static ubyte[seedSizeBytes+1] value;

	private static ubyte[seedSizeBytes] constant; // Hash_DRBG's secret working state value C
	private static uint numGenerated; // Number of values generated with the current seed

	// Maximum number of values generated before automatically reseeding with fresh entropy.
	// The algorithm's spec permits this to be anything less than or equal to 2^48,
	// but we should take care not to overflow our actual countner.
	private enum int maxGenerated = 0x0FFF_FFFF;
	
	private static bool inited = false;
	private void init()
	{
		if(inited)
			return;
		
		// seedMaterial = entropy ~ nonce ~ custom;
		ubyte[entropySizeBytes + nonceSizeBytes + custom.length] seedMaterial = void;
		SystemEntropyStream.read( seedMaterial[0 .. $-custom.length] );
		seedMaterial[$-custom.length .. $] = cast(ubyte[])custom;
		
		// Generate seed for V
		hashDerivation(seedMaterial, null, value[1..$]);
		
		// Generate constant
		value[0] = 0x00;
		hashDerivation(value, null, constant);
		
		numGenerated = 0;
		inited = true;
	}
	
	private void reseed(ubyte[] extraInput=null)
	{
		// seedMaterial = 0x01 ~ V ~ entropy; (Omit optional "additional_input")
		ubyte[value.sizeof + entropySizeBytes] seedMaterial = void;
		seedMaterial[0] = 0x01;
		seedMaterial[1 .. $-entropySizeBytes] = value[1..$];
		SystemEntropyStream.read( seedMaterial[$-entropySizeBytes .. $] );
		
		// Generate seed for V
		hashDerivation(seedMaterial, extraInput, value[1..$]);
		
		// Generate constant
		value[0] = 0x00;
		hashDerivation(value, null, constant);

		numGenerated = 0;
	}
	
	/++
	Fills the buffer with random values using the Hash_DRBG algorithm.
	
	predictionResistance:
	Set to Yes.PredictionResistance for additional protection against
	prediction attacks by forcing a reseed with fresh entropy.
	Default is No.PredictionResistance.
	+/
	void read(ubyte[] buf,
		Flag!"PredictionResistance" predictionResistance = No.PredictionResistance,
		ubyte[] extraInput = null)
	{
		if(numGenerated >= maxGenerated || predictionResistance == Yes.PredictionResistance)
			reseed(extraInput);
		
		if(extraInput)
		{
			value[0] = 0x02;

			TSHA sha;
			sha.put(value);
			sha.put(extraInput);
			ubyte[seedSizeBytes] tempHash;
			tempHash[0..outputSizeBits/8] = sha.finish();
			addHash!seedSizeBytes(value[1..$], tempHash, value[1..$]);
		}
		
		ubyte[seedSizeBytes] workingData = value[1..$];
		if(buf.length > 0)
		while(true)
		{
			// Fill the front of buf with up to seedSizeBytes of random data
			ubyte[outputSizeBits/8] currHash = digest!TSHA(workingData);
			auto length = buf.length < currHash.length? buf.length : currHash.length;
			buf[0..length] = currHash[0..length];
			buf = buf[length..$];
			
			// Buffer filled?
			if(buf.length == 0)
				break;
			
			incrementHash(workingData);
		}
		
		// Update V
		value[0] = 0x03;
		ubyte[seedSizeBytes] hashSum = void;
		hashSum[0 .. outputSizeBits/8] = digest!TSHA(value);
		hashSum[outputSizeBits/8 .. $] = 0;
		addHash!seedSizeBytes(hashSum, value[1..$], hashSum);
		addHash!seedSizeBytes(hashSum, constant, hashSum);
		addHash!seedSizeBytes(hashSum, numGenerated+1, value[1..$]);
		
		numGenerated++;
	}

	///ditto
	void read(ubyte[] buf, ubyte[] extraInput)
	{
		read(buf, No.PredictionResistance, extraInput);
	}
	
	private static void hashDerivation(ubyte[] input, ubyte[] extraInput, ubyte[] buf)
	{
		ubyte counter = 1;
		ulong originalBufLength = buf.length;
		while(buf.length)
		{
			// Generate hashed data
			TSHA sha;
			sha.put(counter);
			sha.put(*(cast(ubyte[8]*) &originalBufLength));
			sha.put(input);
			if(extraInput)
				sha.put(extraInput);
			auto currHash = sha.finish();
			
			// Fill the front of buf with the hashed data
			auto length = buf.length < currHash.length? buf.length : currHash.length;
			buf[0..length] = currHash[0..length];
			buf = buf[length..$];
			
			counter++;
		}
	}
	
	private static void incrementHash(int numBytes)(ref ubyte[numBytes] arr)
	{
		// Endianness (small, big or even weird mixes) doesn't matter since hashes
		// don't have a particularly meaningful least/most significant bit. As
		// long as we're consistent across the RNG instance's lifetime, we're good.

		foreach(ref b; arr)
		{
			b++;
			if(b != 0)
				break;
		}
	}

	private static void addHash(int numBytes)(ubyte[numBytes] arr1,
		ubyte[numBytes] arr2, ubyte[] result)
	{
		// As with incrementHash, endianness doesn't matter here.
		
		enforce(arr1.length == arr2.length);
		enforce(arr1.length == result.length);
		uint carry = 0;
		foreach(i; 0..arr1.length)
		{
			auto sum = arr1[i] + arr2[i] + carry;
			result[i] = sum & 0xFF;
			carry = sum >> 8;
		}
	}

	private static void addHash(int numBytes)(ubyte[numBytes] arr, uint value,
		ubyte[] result)
	{
		// As with incrementHash, endianness doesn't matter here.
		
		enforce(arr.length == result.length);
		uint carry = value;
		foreach(i; 0..arr.length)
		{
			uint sum = arr[i] + carry;
			result[i] = sum & 0xFF;
			carry = sum >> 8;
		}
	}
}

///ditto
alias HashDRBGStream(string custom) = HashDRBGStream!(SHA512, custom);

/// A convenience template to create a UniformRNG from HashDRBGStream.
/// See the WrappedStreamRNG documentation for important information.
template HashDRBG(Elem, TSHA = SHA512, string custom = "D Crypto RNG")
	if(isInstanceOf!(SHA, TSHA))
{
	alias HashDRBG = WrappedStreamRNG!(HashDRBGStream!(TSHA, custom), Elem);
}

///ditto
alias HashDRBG(StaticUByteArr, string custom) = HashDRBG!(StaticUByteArr, SHA512, custom);

static assert(isUniformRNG!(HashDRBG!(ubyte[1]), ubyte[1]));
static assert(isUniformRNG!(HashDRBG!(ubyte[5]), ubyte[5]));
static assert(isUniformRNG!(HashDRBG!ubyte,      ubyte   ));
static assert(isUniformRNG!(HashDRBG!ushort,     ushort  ));
static assert(isUniformRNG!(HashDRBG!uint,       uint    ));
static assert(isUniformRNG!(HashDRBG!ulong,      ulong   ));
static assert(isUniformRNG!(HashDRBG!(uint), uint));
static assert(isUniformRNG!(HashDRBG!(uint, "custom"), uint));
static assert(isUniformRNG!(HashDRBG!(uint, SHA256, "custom"), uint));

version(DAuth_Unittest)
unittest
{
	unitlog("Testing HashDRBGStream.incrementHash");
	
	HashDRBGStream!SHA1 rand;
	ubyte[5] val      = [0xFF, 0xFF, 0b0000_1011, 0x00, 0x00];
	ubyte[5] expected = [0x00, 0x00, 0b0000_1100, 0x00, 0x00];
	
	assert(val != expected);
	rand.incrementHash(val);
	assert(val == expected);
}

version(DAuth_Unittest)
unittest
{
	unitlog("Testing HashDRBGStream.addHash(arr,arr,arr)");
	
	HashDRBGStream!SHA1 rand;
	ubyte[5] val1     = [0xCC, 0x05, 0xFE, 0x01, 0x00];
	ubyte[5] val2     = [0x33, 0x02, 0x9E, 0x00, 0x00];
	ubyte[5] expected = [0xFF, 0x07, 0x9C, 0x02, 0x00];
	ubyte[5] result;
	
	assert(result != expected);
	rand.addHash(val1, val2, result);
	assert(result == expected);
}

version(DAuth_Unittest)
unittest
{
	unitlog("Testing HashDRBGStream.addHash(arr,int,arr)");
	
	HashDRBGStream!SHA1 rand;
	ubyte[5] val1     = [0xCC, 0x05, 0xFE, 0x01, 0x00];
	uint val2         = 0x009E_0233;
	ubyte[5] expected = [0xFF, 0x07, 0x9C, 0x02, 0x00];
	ubyte[5] result;
	
	assert(result != expected);
	rand.addHash(val1, val2, result);
	assert(result == expected);
}

/++
Takes a RandomStream (ex: SystemEntropyStream or HashDRBGStream) and
wraps it into a UniformRNG InputRange.

Note that, to conform to the expected InputRange interface, this must keep a
copy of the last generated value in memory. For security purposes, it may
occasionally be appropriate to make an extra popFront() call before and/or
after retreiving entropy values. This may decrease the chance of using
a compromized entropy value in the event of a memory-sniffing attacker.
+/
struct WrappedStreamRNG(RandomStream, StaticUByteArr)
	if(isRandomStream!RandomStream && isStaticArray!StaticUByteArr && is(ElementType!StaticUByteArr==ubyte))
{
	enum isUniformRandom = true; /// Mark this as a Rng
	
	private StaticUByteArr _front;
	private bool inited = false;
	private static RandomStream stream;
	
	/// Implements an InputRange
	@property StaticUByteArr front()
	{
		if(!inited)
		{
			popFront();
			inited = true;
		}
		
		return _front;
	}
	
	///ditto
	void popFront()
	{
		stream.read(_front);
	}
	
	/// Infinite range. Never empty.
	enum empty = false;
	
	/// Smallest generated value.
	enum min = StaticUByteArr.init;
	
	/// Largest generated value.
	static @property StaticUByteArr max()
	{
		StaticUByteArr val = void;
		val[] = 0xFF;
		return val;
	}
}

///ditto
struct WrappedStreamRNG(RandomStream, UIntType)
	if(isRandomStream!RandomStream && isUnsigned!UIntType)
{
	private WrappedStreamRNG!(RandomStream, ubyte[UIntType.sizeof]) bytesImpl;
	
	enum isUniformRandom = true; /// Mark this as a Rng
	
	private UIntType _front;
	private bool inited = false;
	
	/// Implements an InputRange
	@property UIntType front()
	{
		auto val = bytesImpl.front;
		return *(cast(UIntType*) &val);
	}
	
	///ditto
	void popFront()
	{
		bytesImpl.popFront();
	}
	
	enum empty = false; /// Infinite range. Never empty.
	enum min = UIntType.min; /// Smallest generated value.
	enum max = UIntType.max; /// Largest generated value.
}

version(DAuth_Unittest)
unittest
{
	alias RandStreamTypes = TypeTuple!(
		SystemEntropyStream,
		HashDRBGStream!SHA1,
		HashDRBGStream!SHA224,
		HashDRBGStream!SHA256,
		HashDRBGStream!SHA384,
		HashDRBGStream!SHA512,
		HashDRBGStream!SHA512_224,
		HashDRBGStream!SHA512_256,
		HashDRBGStream!(SHA512, "other custom str"),
	);
	
	unitlog("Testing SystemEntropyStream/HashDRBGStream");
	foreach(RandStream; RandStreamTypes)
	{
		//unitlog("Testing RandStream: "~RandStream.stringof);
		
		RandStream rand;
		ubyte[] values1;
		ubyte[] values2;
		values1.length = 10;
		values2.length = 10;
		
		rand.read(values1);
		assert(values1 != typeof(values1).init);
		assert(values1[0..4] != values1[4..8]);
		rand.read(values2);
		assert(values1 != values2);
		
		auto randCopy = rand;
		rand.read(values1);
		randCopy.read(values2);
		assert(values1 != values2);
		
		static if(!is(RandStream == SystemEntropyStream))
		{
			values2[] = ubyte.init;

			values1[] = ubyte.init;
			rand.read(values1, Yes.PredictionResistance);
			assert(values1 != values2);
			
			values1[] = ubyte.init;
			rand.read(values1, cast(ubyte[])"additional input");
			assert(values1 != values2);
			
			values1[] = ubyte.init;
			rand.read(values1, Yes.PredictionResistance, cast(ubyte[])"additional input");
			assert(values1 != values2);
		}
	}
}

version(DAuth_Unittest)
unittest
{
	foreach(Rand; TypeTuple!(SystemEntropy, HashDRBG))
	{
		unitlog("Testing Rand's min/max: "~Rand.stringof);

		assert(Rand!(ubyte[1]).min == [0x00]);
		assert(Rand!(ubyte[1]).max == [0xFF]);
		assert(Rand!(ubyte[5]).min == [0x00,0x00,0x00,0x00,0x00]);
		assert(Rand!(ubyte[5]).max == [0xFF,0xFF,0xFF,0xFF,0xFF]);
		assert(Rand!(ubyte   ).min == ubyte .min);
		assert(Rand!(ubyte   ).max == ubyte .max);
		assert(Rand!(ushort  ).min == ushort.min);
		assert(Rand!(ushort  ).max == ushort.max);
		assert(Rand!(uint    ).min == uint  .min);
		assert(Rand!(uint    ).max == uint  .max);
		assert(Rand!(ulong   ).min == ulong .min);
		assert(Rand!(ulong   ).max == ulong .max);
	}
}

version(DAuth_Unittest)
unittest
{
	alias RandTypes = TypeTuple!(
		SystemEntropy!ulong,
		SystemEntropy!ubyte,
		SystemEntropy!ushort,
		SystemEntropy!uint,
		SystemEntropy!(ubyte[5]),
		SystemEntropy!(ubyte[1024]),
		HashDRBG!(ulong, SHA1),
		HashDRBG!(ulong, SHA224),
		HashDRBG!(ulong, SHA256),
		HashDRBG!(ulong, SHA384),
		HashDRBG!(ulong, SHA512),
		HashDRBG!(ulong, SHA512_224),
		HashDRBG!(ulong, SHA512_256),
		HashDRBG!(ulong, SHA512, "other custom str"),
		HashDRBG!(ubyte, SHA512),
		HashDRBG!(ushort,  SHA512),
		HashDRBG!(uint,    SHA512),
		HashDRBG!(ubyte[5], SHA512),
		HashDRBG!(ubyte[1024], SHA512),
	);
	
	unitlog("Testing SystemEntropy/HashDRBG");
	foreach(Rand; RandTypes)
	{
		//unitlog("Testing Rand: "~Rand.stringof);

		Rand rand;
		assert(!rand.empty);
		
		assert(rand.front == rand.front);
		auto val = rand.front;
		assert(val != ElementType!(Rand).init);

		rand.popFront();
		assert(val != rand.front);

		auto randCopy = rand;
		assert(rand.front == randCopy.front);
		rand.popFront();
		randCopy.popFront();
		assert(rand.front != randCopy.front);
	}
}
