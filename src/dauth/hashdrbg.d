/++
DAuth - Salted Hashed Password Library for D
Hash_DRBG Cryptographic Random Number Generator
+/

module dauth.hashdrbg;

import std.conv;
import std.exception;
import std.random;
import std.range;
import std.stdio;
import std.traits;
import std.typecons;
import std.typetuple;

import dauth.core;

import std.digest.sha;

// TemplateArgsOf only exists in Phobos of DMD 2.066 and up
private struct dummy(T) {}
static if(!is(std.traits.TemplateArgsOf!(dummy!int)))
	private alias TemplateArgsOf = DAuth_TemplateArgsOf;

version(Windows)
{
	import std.c.windows.windows;
	import core.runtime;
}

/++
Check if T is a stream-like random number generator.

Because std.stream is pending a full replacement, be aware that
stream-like random number generators currently use a temporary
design that may change once a new std.stream is available.
+/
enum isRandomStream(T) =
	is(typeof({
		static assert(T.isUniformRandomStream);
		T t;
		ubyte[] buf;
		t.read(buf);
		t.read(buf, No.PredictionResistance);
	}));

static assert(isRandomStream!(SystemEntropyStream!()));
static assert(isRandomStream!(HashDRBGStream!()));
static assert(!isRandomStream!(SystemEntropy!uint));
static assert(!isRandomStream!(HashDRBG!uint));
static assert(!isRandomStream!uint);
static assert(!isRandomStream!File);

/++
The underlying stream-like interface for SystemEntropy.

On Windows, pathToRandom and pathToStrongRandom must be null because Windows
uses a system call, not a file path, to retreive system entropy.

On Posix, pathToRandom must NOT be null. If pathToStrongRandom is null,
then pathToStrongRandom is assumed to be pathToRandom.

Because std.stream is pending a full replacement, be aware that
stream-like random number generators currently use a temporary
design that may change once a new std.stream is available.

Declaration:
-----------------------
struct SystemEntropyStream(string pathToRandom = defaultPathToRandom,
	string pathToStrongRandom = defaultPathToStrongRandom) {...}
-----------------------
+/
struct SystemEntropyStream(string pathToRandom = defaultPathToRandom,
	string pathToStrongRandom = defaultPathToStrongRandom)
{
	enum isUniformRandomStream = true; /// Mark this as a Rng Stream

	version(Windows)
	{
		import std.c.windows.windows;
		import core.runtime;

		static assert(pathToRandom is null, "On Windows, SystemEntropyStream's pathToRandom must be null");
		static assert(pathToStrongRandom is null, "On Windows, SystemEntropyStream's pathToStrongRandom must be null");

		private static HMODULE _advapi32;
		private static extern(Windows) BOOL function(void*, uint) _RtlGenRandom;
	}
	else version(Posix)
	{
		import std.stdio : File, _IONBF;

		static assert(pathToRandom !is null, "On Posix, SystemEntropyStream's pathToRandom must NOT be null");

		private static File devRandom;
		private static File devStrongRandom;
	}
	else
		static assert(0);

	/++
	Fills the buffer with entropy from the system-specific entropy generator.
	Automatically opens SystemEntropyStream if it's closed.

	If predictionResistance is Yes.PredictionResistance, then this will read
	from a secondary source (if available), such as /dev/random instead of
	/dev/urandom, which may block for a noticable amount of time to ensure
	a minimum amount of estimated entropy is available. If no secondary
	source is available, then predictionResistance is ignored.

	Optional_Params:
	predictionResistance - Default value is 'No.PredictionResistance'
	+/
	static void read(ubyte[] buf, Flag!"PredictionResistance" predictionResistance = No.PredictionResistance)
	{
		open();

		version(Windows)
		{
			enforce(buf.length < uint.max, "Cannot read more than uint.max bytes from RtlGenRandom");
			_RtlGenRandom(buf.ptr, cast(uint)buf.length);
		}
		else version(Posix)
		{
			if(predictionResistance == Yes.PredictionResistance && pathToStrongRandom)
				devStrongRandom.rawRead(buf);
			else
				devRandom.rawRead(buf);
		}
		else
			static assert(0);
	}

	/++
	Establishes a handle/connection to the system-specific entropy generator.
	Does nothing if already open.
	+/
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
			static void openFile(ref File f, string path)
			{
				if(!f.isOpen)
				{
					f = File(path);

					// Disable buffering for security, and to avoid consuming
					// more system entropy than necessary.
					f.setvbuf(null, _IONBF);
				}
			}

			openFile(devRandom, pathToRandom);
			if(pathToStrongRandom)
				openFile(devStrongRandom, pathToStrongRandom);
		}
		else
			static assert(0);
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
			if(devStrongRandom.isOpen)
				devStrongRandom.close();
		}
		else
			static assert(0);
	}

	/++
	Check whether SystemEntropyStream is currently connected to with the
	system-specific entropy generator.
	+/
	static @property bool isOpen()
	{
		version(Windows)
			return _advapi32 && _RtlGenRandom;
		else version(Posix)
			return devRandom.isOpen && (!pathToStrongRandom || devStrongRandom.isOpen);
		else
			static assert(0);
	}

	/// Automatically close upon module destruction.
	static ~this()
	{
		close();
	}
}

/++
Reads random entropy from a system-specific cryptographic random number
generator. On Windows, this loads ADVAPI32.DLL and uses RtlGenRandom.
On Posix, this reads from a file (by default, "/dev/urandom" normally and
"/dev/random" when Yes.PredictionResistance is requested). The speed
and cryptographic security of this is dependent on your operating system.

In most cases, this should not be used directly. It quickly consumes
available system entropy, which can decrease the cryptographic RNG
effectiveness across the whole computer and, on Linux, can cause reads from
"/dev/random" to stall for noticably long periods of time. Instead,
this is best used for seeding cryptographic psuedo-random number generators,
such as HashDRBG.

Optionally, you can use open() and close() to control the lifetime of
SystemEntropyStream's system handles (ie, loading/uloading ADVAPI32.DLL and
opening/closing pathToRandom). But this is not normally necessary since
SystemEntropyStream automatically opens them upon reading and closes upon
module destruction.

On Windows, pathToRandom and pathToStrongRandom must be null because Windows
uses a system call, not a file path, to retreive system entropy.

On Posix, pathToRandom must NOT be null. If pathToStrongRandom is null,
then pathToStrongRandom is assumed to be pathToRandom.

This is a convenience alias for WrappedStreamRNG!(SystemEntropyStream, Elem).

Note that to conform to the expected InputRange interface, this must keep a
copy of the last generated value in memory. For security purposes, it may
occasionally be appropriate to make an extra popFront() call before and/or
after retreiving entropy values. This may decrease the chance of using
a compromized entropy value in the event of a memory-sniffing attacker.

Optional_Params:
pathToRandom - Default value is 'defaultPathToRandom'

pathToStrongRandom - Default value is 'defaultPathToStrongRandom'
+/
alias SystemEntropy(Elem, string pathToRandom = defaultPathToRandom,
	string pathToStrongRandom = defaultPathToStrongRandom) =
	WrappedStreamRNG!(SystemEntropyStream!(pathToRandom, pathToStrongRandom), Elem);

version (StdDdoc)
{
	/++
	The path to the default OS-provided cryptographic entropy generator.
	This should not be a blocking generator.

	On Posix, this is "/dev/urandom". On Windows is empty string, because
	Windows uses a system call, not a file path, to retreive system entropy.
	+/
	enum string defaultPathToRandom = null;

	/++
	The path to an OS-provided cryptographic entropy generator to be used
	when Yes.PredictionResistance is requested. This should be at least as
	strong as defaultPathToRandom. But unlike defaultPathToRandom, this may
	be a generator that blocks when system entropy is low.

	On Posix, this is "/dev/random". On Windows is empty string, because
	Windows uses a system call, not a file path, to retreive system entropy.
	+/
	enum string defaultPathToStrongRandom = null;
}
else version (Windows)
{
	enum string defaultPathToRandom = null;
	enum string defaultPathToStrongRandom = null;
}
else version (Posix)
{
	enum defaultPathToRandom = "/dev/urandom";
	enum defaultPathToStrongRandom = "/dev/random";
}
else
	static assert(0);

static assert(isUniformRNG!(SystemEntropy!(ubyte[1]), ubyte[1]));
static assert(isUniformRNG!(SystemEntropy!(ubyte[5]), ubyte[5]));
static assert(isUniformRNG!(SystemEntropy!ubyte,      ubyte   ));
static assert(isUniformRNG!(SystemEntropy!ushort,     ushort  ));
static assert(isUniformRNG!(SystemEntropy!uint,       uint    ));
static assert(isUniformRNG!(SystemEntropy!ulong,      ulong   ));

/++
The underlying stream-like interface for SystemEntropy.

TSHA: Any SHA-1 or SHA-2 digest type. Default is SHA512.

custom: The Hash_DRBG algorithm's personalization string. You
can optionally set this to any specific value of your own choosing for
improved security.

EntropyStream: The source of entropy from which to draw.
The default is SystemEntropyStream!(), but can be overridden. If you provide
your own, then it's your responsibility to ensure your entropy source is
non-deterministic.

Because std.stream is pending a full replacement, be aware that
stream-like random number generators currently use a temporary
design that may change once a new std.stream is available.

Declaration:
-----------------------
struct HashDRBGStream(TSHA = SHA512, string custom = "D Crypto RNG", EntropyStream = SystemEntropyStream!())
	if(isInstanceOf!(SHA, TSHA))
	{...}
-----------------------
+/
struct HashDRBGStream(TSHA = SHA512, string custom = "D Crypto RNG", EntropyStream = SystemEntropyStream!())
	if(isInstanceOf!(SHA, TSHA))
{
	enum isUniformRandomStream = true; /// Mark this as a Rng Stream

	// In bits. This is the same as the SHA's digestSize
	private enum outputSizeBits = TemplateArgsOf!(TSHA)[1];

	static if (outputSizeBits < 384)
		private enum seedSizeBytes = 440/8; // In bytes
	else
		private enum seedSizeBytes = 888/8; // In bytes

	// Securty strength 256 bits. Less could provide insufficitent security,
	// but more would consume more of the system's entropy for no benefit.
	// See NIST's [SP800-90A] and [SP800-57] for details on this value.
	private enum entropySizeBytes = 256/8;

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

	/++
	If your security needs are high enough that you'd rather risk blocking
	for an arbitrarily-long period of time while sufficient system entropy
	builds, than risk generating values from potentially insufficient entropy
	(ex, if you'd rather reseed from Linux's /dev/random than /dev/urandom),
	then set this to Yes.PredictionResistance. The next time a value is
	generated, the internal state will first be replenished with additional
	entropy, potentially from a blocking source.

	After the next value is generated, this will automatically reset back
	to No.PredictionResistance to avoid needlessly consuming the system's
	available entropy. Note that forcefully setting this to Yes.PredictionResistance
	before each and every value generated is NOT cryptographically necessary,
	can quickly starve the system of entropy, and should not be done.

	Default is No.PredictionResistance.

	This setting is for changing read()'s default bahavior. Individual calls
	to read() can manually override this per call.
	+/
	Flag!"PredictionResistance" predictionResistance = No.PredictionResistance;

	/++
	Further improve security by setting Hash_DRBG's optional "additional input"
	for each call to read(). This can be set to a new value before each read()
	call for maximum effect.

	This setting is for changing read()'s default bahavior. Individual calls
	to read() can manually override this per call.
	+/
	ubyte[] extraInput = null;

	private static bool inited = false;
	private void init()
	{
		if(inited)
			return;

		// seedMaterial = entropy ~ nonce ~ custom;
		ubyte[entropySizeBytes + nonceSizeBytes + custom.length] seedMaterial = void;
		EntropyStream.read( seedMaterial[0 .. $-custom.length], predictionResistance );
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
		// seedMaterial = 0x01 ~ V ~ entropy;
		ubyte[value.sizeof + entropySizeBytes] seedMaterial = void;
		seedMaterial[0] = 0x01;
		seedMaterial[1 .. $-entropySizeBytes] = value[1..$];
		EntropyStream.read( seedMaterial[$-entropySizeBytes .. $], predictionResistance );

		// Generate seed for V
		hashDerivation(seedMaterial, extraInput, value[1..$]);

		// Generate constant
		value[0] = 0x00;
		hashDerivation(value, null, constant);

		numGenerated = 0;
	}

	/++
	Fills the buffer with random values using the Hash_DRBG algorithm.

	overridePredictionResistance:
	Override this.predictionResistance setting for this call only.

	overrideExtraInput:
	Override this.extraInput setting for this call only.
	+/
	void read(ubyte[] buf)
	{
		read(buf, predictionResistance, extraInput);
	}

	///ditto
	void read(ubyte[] buf, ubyte[] overrideExtraInput)
	{
		read(buf, predictionResistance, overrideExtraInput);
	}

	///ditto
	void read(ubyte[] buf, Flag!"PredictionResistance" overridePredictionResistance)
	{
		read(buf, overridePredictionResistance, extraInput);
	}

	///ditto
	void read(ubyte[] buf,
		Flag!"PredictionResistance" overridePredictionResistance,
		ubyte[] overrideExtraInput)
	{
		init();

		if(numGenerated >= maxGenerated || overridePredictionResistance == Yes.PredictionResistance)
			reseed(overrideExtraInput);

		predictionResistance = No.PredictionResistance;

		if(overrideExtraInput)
		{
			value[0] = 0x02;

			TSHA sha;
			sha.put(value);
			sha.put(overrideExtraInput);
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

/++
Cryptographic random number generator Hash_DRBG, as defined in
NIST's $(LINK2 http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf, SP800-90A).

The Hash_DRBG algorithm ("Hash - Deterministic Random Bit Generator") uses
SHA-2 (or optionally SHA-1) to stretch the useful life of a non-deterministic
$(LINK2 https://en.wikipedia.org/wiki/Entropy_%28information_theory%29, entropy)
source for security and cryptographic purposes, such as
$(LINK2 http://en.wikipedia.org/wiki/One-time_password, single-use tokens),
$(LINK2 http://en.wikipedia.org/wiki/Cryptographic_nonce, nonces)
or $(LINK2 http://en.wikipedia.org/wiki/Salt_%28cryptography%29, password salts).

While technically deterministic, Hash_DRBG is not intended for deterministic,
repeatable uses of psuedo-random number generation (such as generating randomized
interactive worlds with minimal-storage requirements - for which something like
Mt19937 would be better suited). For the sake of security, the algorithm is
intentionally defined to not support direct seeding and to automatically
accumulate (but never discard) entropy from not only a pre-determined source
of unpredictable entropy, but also from actual usage patterns. In that
spirit, this implementation is non-seedable, non-ForwardRange (only InputRange),
and all instances share a static state (albeit per thread, per EntropyStream type).

Mainly through the underlying HashDRBGStream (accessed via the $(D stream) member),
this supports the optional features of the Hash_DRBG algorithm. Specifically,
prediction resistance via forced reseeding, providing additional input for
each value generated, and custom personalization strings.

TSHA: Any SHA-1 or SHA-2 digest type. Default is SHA512.

custom: The Hash_DRBG algorithm's personalization string. You
can optionally set this to any specific value of your own choosing for
extra security.

EntropyStream: The source of entropy from which to draw.
The default is SystemEntropyStream!(), but can be overridden. If you provide
your own, then it's your responsibility to ensure your entropy source is
non-deterministic.

This is a convenience alias for WrappedStreamRNG!(HashDRBGStream, Elem).

Note that to conform to the expected InputRange interface, this must keep a
copy of the last generated value in memory. For security purposes, it may
occasionally be appropriate to make an extra popFront() call before and/or
after retrieving entropy values. This may decrease the chance of using
a compromised entropy value in the event of a memory-sniffing attacker.

Declaration:
-----------------------
struct HashDRBGStream(TSHA = SHA512, string custom = "D Crypto RNG", EntropyStream = SystemEntropyStream!())
	if(isInstanceOf!(SHA, TSHA))
	{...}
-----------------------
+/
template HashDRBG(Elem, TSHA = SHA512, string custom = "D Crypto RNG", EntropyStream = SystemEntropyStream!())
	if(isInstanceOf!(SHA, TSHA))
{
	alias HashDRBG = WrappedStreamRNG!(HashDRBGStream!(TSHA, custom, EntropyStream), Elem);
}

static assert(isUniformRNG!(HashDRBG!(ubyte[1]), ubyte[1]));
static assert(isUniformRNG!(HashDRBG!(ubyte[5]), ubyte[5]));
static assert(isUniformRNG!(HashDRBG!ubyte,      ubyte   ));
static assert(isUniformRNG!(HashDRBG!ushort,     ushort  ));
static assert(isUniformRNG!(HashDRBG!uint,       uint    ));
static assert(isUniformRNG!(HashDRBG!ulong,      ulong   ));
static assert(isUniformRNG!(HashDRBG!(uint), uint));
static assert(isUniformRNG!(HashDRBG!(uint, SHA256), uint));
static assert(isUniformRNG!(HashDRBG!(uint, SHA256, "custom"), uint));
static assert(isUniformRNG!(HashDRBG!(uint, SHA256, "custom", SystemEntropyStream!()), uint));

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

Note that to conform to the expected InputRange interface, this must keep a
copy of the last generated value in memory. If using this for security-related
purposes, it may occasionally be appropriate to make an extra popFront()
call before and/or after retreiving entropy values. This may decrease the
chance of using a compromized entropy value in the event of a
memory-sniffing attacker.

Declaration:
-----------------------
struct WrappedStreamRNG(RandomStream, StaticUByteArr)
	if(isRandomStream!RandomStream && isStaticArray!StaticUByteArr && is(ElementType!StaticUByteArr==ubyte))
	{...}
-----------------------
+/
struct WrappedStreamRNG(RandomStream, StaticUByteArr)
	if(isRandomStream!RandomStream && isStaticArray!StaticUByteArr && is(ElementType!StaticUByteArr==ubyte))
{
	enum isUniformRandom = true; /// Mark this as a Rng

	private StaticUByteArr _front;
	private bool inited = false;

	/// Access to underlying RandomStream so RNG-specific functionality can be accessed.
	RandomStream stream;

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
		SystemEntropyStream!(),
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

		static if(!is(RandStream == SystemEntropyStream!()))
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
	// Don't test ubyte or ushort versions here because legitimate repeated
	// values are too likely and would trigger a failure and unfounded worry.

	alias RandTypes = TypeTuple!(
		SystemEntropy!ulong,
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
