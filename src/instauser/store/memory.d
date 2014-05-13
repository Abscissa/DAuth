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
}

version(InstaUser_Unittest)
unittest
{
	unitlog("Testing MemoryStore");

	static assert(isUserStore!MemoryStore);
	
	auto store = new MemoryStore();
	assert(store.lookup.length == 0);
	
	assertNotThrown!UserAlreadyExistsException( store.createUser("Mo",  dupPassword("stuffjunk")) );
	assertNotThrown!UserAlreadyExistsException( store.createUser("Joe", dupPassword("pass123"  )) );
	assertNotThrown!UserAlreadyExistsException( store.createUser("Cho", dupPassword("test pass")) );

	assert( store.lookup.keys.sort == ["Cho", "Joe", "Mo"] );
	assert( store.userExists("Mo")  );
	assert( store.userExists("Joe") );
	assert( store.userExists("Cho") );
	assert( !store.userExists("Herman") );
	assert( !store.userExists("") );
	
	assertNotThrown!UserNotFoundException( store.removeUser("Mo") );

	assert( store.lookup.keys.sort == ["Cho", "Joe"] );
	assert( !store.userExists("Mo") );
	assert( store.userExists("Joe") );
	assert( store.userExists("Cho") );
	
	assertThrown!UserNotFoundException( store.removeUser("Mo") );
	assertThrown!UserNotFoundException( store.removeUser("Herman") );

	assert( store.lookup.keys.sort == ["Cho", "Joe"] );
	assert( !store.userExists("Mo") );
	assert( store.userExists("Joe") );
	assert( store.userExists("Cho") );
	
	assert( store.validateUser ("Joe",    dupPassword("pass123")) );
	assert( !store.validateUser("Cho",    dupPassword("pass123")) );
	assert( !store.validateUser("Herman", dupPassword("pass123")) );

	assert( !store.validateUser("Joe",    dupPassword("test pass")) );
	assert( store.validateUser ("Cho",    dupPassword("test pass")) );
	assert( !store.validateUser("Herman", dupPassword("test pass")) );
	
	assertNotThrown!UserNotFoundException( store.modifyUser("Cho", dupPassword("pass123")) );
	assert( store.validateUser ("Cho", dupPassword("pass123"  )) );
	assert( !store.validateUser("Cho", dupPassword("test pass")) );
	
	assert( store.getHash("Joe").toString() != store.getHash("Cho").toString() );
}
