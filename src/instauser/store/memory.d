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
	assertNotThrown( instaUser.wipeEverythingAndInit() );
	assert( instaUser.getUserCount() == 0 );
	
	assertNotThrown( instaUser.wipeEverythingAndInit() );
	assert( instaUser.getUserCount() == 0 );
	
	assertNotThrown!UserAlreadyExistsException( instaUser.createUser("Mo",  dupPassword("stuffjunk")) );
	assertNotThrown!UserAlreadyExistsException( instaUser.createUser("Joe", dupPassword("pass123"  )) );
	assertNotThrown!UserAlreadyExistsException( instaUser.createUser("Cho", dupPassword("test pass")) );

	assert( instaUser.getUserCount() == 3 );
	assert( instaUser.userExists("Mo")  );
	assert( instaUser.userExists("Joe") );
	assert( instaUser.userExists("Cho") );
	assert( !instaUser.userExists("Herman") );
	assert( !instaUser.userExists("") );
	
	assertNotThrown!UserNotFoundException( instaUser.removeUser("Mo") );

	assert( instaUser.getUserCount() == 2 );
	assert( !instaUser.userExists("Mo") );
	assert( instaUser.userExists("Joe") );
	assert( instaUser.userExists("Cho") );
	
	assertThrown!UserNotFoundException( instaUser.removeUser("Mo") );
	assertThrown!UserNotFoundException( instaUser.removeUser("Herman") );

	assert( instaUser.getUserCount() == 2 );
	assert( !instaUser.userExists("Mo") );
	assert( instaUser.userExists("Joe") );
	assert( instaUser.userExists("Cho") );
	
	assert( instaUser.validateUser ("Joe",    dupPassword("pass123")) );
	assert( !instaUser.validateUser("Cho",    dupPassword("pass123")) );
	assert( !instaUser.validateUser("Herman", dupPassword("pass123")) );

	assert( !instaUser.validateUser("Joe",    dupPassword("test pass")) );
	assert( instaUser.validateUser ("Cho",    dupPassword("test pass")) );
	assert( !instaUser.validateUser("Herman", dupPassword("test pass")) );
	
	assertNotThrown!UserNotFoundException( instaUser.modifyUser("Cho", dupPassword("pass123")) );
	assert( instaUser.validateUser ("Cho", dupPassword("pass123"  )) );
	assert( !instaUser.validateUser("Cho", dupPassword("test pass")) );
	
	assert( instaUser.store.getHash("Joe").toString() != instaUser.store.getHash("Cho").toString() );

	assert( instaUser.getUserCount() == 2 );
	assertNotThrown( instaUser.wipeEverythingAndInit() );
	assert( instaUser.getUserCount() == 0 );
	assertNotThrown( instaUser.store.wipeEverything() );
	
	// Should not fail even if already wiped
	assertNotThrown( instaUser.store.wipeEverything() );
}
