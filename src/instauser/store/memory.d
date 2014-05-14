/// InstaUser - User Account Library for D
/// Data Store: In Memory
///
/// Main module: $(LINK2 index.html,instauser)$(BR)

module instauser.store.memory;

import std.digest.digest;
import std.exception;

import dauth.core;
import instauser.core;

///
class MemoryStore
{
	private shared string[string] lookup; // lookup[name] == salted hash string
	
	///
	bool create(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		if(name in lookup)
			return false;
		
		lookup[name] = hash.toString();
		return true;
	}
	
	///
	bool modify(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		if(auto pHash = name in lookup)
		{
			*pHash = hash.toString();
			return true;
		}
		
		return false;
	}
	
	///
	NullableHash!Digest getHash(string name)
	{
		if(auto pHash = name in lookup)
			return NullableHash!Digest( parseHash(*pHash) );
		
		return NullableHash!Digest();
	}
	
	///
	bool remove(string name)
	{
		if(name !in lookup)
			return false;
		
		lookup.remove(name);
		return true;
	}
	
	///
	ulong getUserCount()
	{
		return lookup.length;
	}
	
	///
	void wipeEverything()
	{
		lookup.destroy();
		assert(lookup.length == 0);
	}
	
	///
	void init()
	{
		// Nothing to do
	}
}

version(InstaUser_Unittest)
unittest
{
	unitlog("Testing MemoryStore");

	static assert(isUserStore!MemoryStore);
	static assert(hasGetUserCount!MemoryStore);
	
	auto store = new MemoryStore();
	assert( store.getUserCount() == 0 );
	
	auto instaUser = InstaUser!MemoryStore(store);
	assert( instaUser.getUserCount() == 0 );
	
	// Run standard tests
	instaUser.unittestStore();
}
