/// InstaUser-Store - User Account Library for D
/// Data Store: In Memory
///
/// Main module: $(LINK2 ../index.html,instauser.store)$(BR)

module instauser.store.storage.memory;

import std.digest.digest;
import std.exception;

import instauser.basic.core;
import instauser.store.core;

/++
A non-permanent in-memory UserStore. Being memory-only, this will be wiped
as soon as the program ends or the object gets garbage collected, unless you
manually saved MemoryStore.rawStore to permanent storage.

If you do need permanent storage (which is likely the case), you should
use a different UserStore designed for permanemt storage, such as
instauser.store.mysqln.MySQLNativeStore.
+/
class MemoryStore
{
	/// rawStore[name] == salted hash string
	/// 
	/// This is public in order to allow entended functionality. For
	/// example, (de)serialization to a file.
	shared string[string] rawStore;
	
	/// Implement a UserStore: Create a new user, returning false if user already exists.
	bool create(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		if(name in rawStore)
			return false;
		
		rawStore[name] = hash.toString();
		return true;
	}
	
	/// Implement a UserStore: Change a user's password, returning false if user doesn't exist.
	bool modify(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		if(auto pHash = name in rawStore)
		{
			*pHash = hash.toString();
			return true;
		}
		
		return false;
	}
	
	/// Implement a UserStore: Retreive a user's password hash, returning null if user doesn't exist.
	NullableHash!Digest getHash(string name)
	{
		if(auto pHash = name in rawStore)
			return NullableHash!Digest( parseHash(*pHash) );
		
		return NullableHash!Digest();
	}
	
	/// Implement a UserStore: Permanently delete a user.
	bool remove(string name)
	{
		if(name !in rawStore)
			return false;
		
		rawStore.remove(name);
		return true;
	}
	
	/// Implement optional UserStore feature: Retrive number of users in the store.
	ulong getUserCount()
	{
		return rawStore.length;
	}
	
	/// Implement a UserStore: PERMANENTLY DELETES ALL user data in the store.
	void wipeEverything()
	{
		rawStore.destroy();
		assert(rawStore.length == 0);
	}
	
	/// Implement a UserStore: Initialize a new store. The store is assumed
	/// to have already been wiped, or have never previously existed.
	void init()
	{
		// Don't need to do anything.
	}
}

version(InstaUserStore_Unittest)
unittest
{
	unitlog("Testing MemoryStore");

	static assert(isUserStore!MemoryStore);
	static assert(hasGetUserCount!MemoryStore);
	
	auto store = new MemoryStore();
	assert( store.getUserCount() == 0 );
	
	auto instaUser = InstaUserStore!MemoryStore(store);
	assert( instaUser.getUserCount() == 0 );
	
	// Run standard tests
	instaUser.unittestStore();
}
