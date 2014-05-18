/// InstaUser - User Account Library for D
/// Core module
///
/// Main module: $(LINK2 index.html,instauser)$(BR)

module instauser.core;

import std.digest.digest;
import std.exception;
import std.typecons;

import dauth.core;

// Manually import this to work around RDMD linking issue in Vibe.d
version(Have_vibe_d)
	import vibe.internal.meta.traits;

version(InstaUser_Unittest)
{
	version(InstaUser_Unittest_Quiet) {} else
		version = Loud_Unittest;
	
	version(Loud_Unittest)
		import std.stdio;
	
	void unitlog(string str)
	{
		version(Loud_Unittest)
		{
			writeln("unittest InstaUser: ", str);
			stdout.flush();
		}
	}
}

///
enum bool isUserStore(T, TDigest) = isUserStore!T && isUserStoreImpl!(T, TDigest);

///ditto
enum bool isUserStore(T) = isUserStoreImpl!(T, Digest);

private template isUserStoreImpl(T, TDigest)
{
	enum isUserStoreImpl = 
		isAnyDigest!TDigest &&
		is(typeof((){
			T t;
			bool succ;
			succ = t.create!TDigest("name", Hash!TDigest());
			succ = t.modify!TDigest("name", Hash!TDigest());
			succ = t.remove("name");
			Hash!Digest hash = t.getHash("name");
			t.wipeEverything();
			t.init();
		}));
}

static assert(!isUserStore!(int,    int));
static assert(!isUserStore!(Object, Object));
static assert(!isUserStore!(int,    Digest));
static assert(!isUserStore!(Object, Digest));
static assert(!isUserStore!int);
static assert(!isUserStore!Object);

///
enum hasGetUserCount(T) = is(typeof((){
	T t;
	ulong x = t.getUserCount();
}));

///
alias NullableHash(TDigest) = Nullable!(Hash!TDigest);

///
class UserAlreadyExistsException : Exception
{
	this(string name)
	{
		super("User already exists: "~name);
	}
}

///
class UserNotFoundException : Exception
{
	this(string name)
	{
		super("User not found: "~name);
	}
}

///
struct InstaUser(Store)
{
	Store store;
	
	///
	this(Store store)
	{
		this.store = store;
	}
	
	///
	void createUser(TDigest = DefaultDigest)
		(string name, Password pass)
		if(isUserStore!(Store, TDigest))
	{
		if(!store.create(name, makeHash(pass)))
			throw new UserAlreadyExistsException(name);
	}

	///
	void modifyUser(TDigest = DefaultDigest)
		(string name, Password pass)
		if(isUserStore!(Store, TDigest))
	{
		auto hash = makeHash(pass);

		if(!store.modify(name, hash))
			throw new UserNotFoundException(name);
	}

	///
	void removeUser(string name)
	{
		if(!store.remove(name))
			throw new UserNotFoundException(name);
	}

	///
	bool validateUser(string name, Password pass)
	{
		auto hash = store.getHash(name);

		if(hash.isNull())
		{
			// To increase difficulty of username harvesting via timing attacks,
			// don't just immediately return false. Instead check it against a
			// fake salted password hash of 8 null bytes.
			//
			// Note: It would be better if this somehow used the same digest used
			// by most user accounts in the system.
			hash = NullableHash!Digest(parseHash(
				"[SHA512]7YGYyyN1GwUlbnYwX3eXaN+ruTPvBRH/5BIa2/zmuu4=$x946sFuSCTJpWv8jIgeAPHZBM0a9iBRorGY8qjqZhnCzT292dz7eXEYtjS1YdTgQmMUk9m7EGeU7bUBad6GSGg=="
			));
		}
		
		return isPasswordCorrect(pass, hash.get());
	}

	///
	bool userExists(string name)
	{
		return !store.getHash(name).isNull();
	}

	///
	ulong getUserCount()() if(hasGetUserCount!Store)
	{
		return store.getUserCount();
	}

	///
	void wipeEverythingAndInit()
	{
		store.wipeEverything();
		store.init();
	}
	
	/// Run standard set of tests on an InstaUser user store.
	///
	/// This will COMPLETELY DESTROY all data in the store, so it only be used
	/// on a test store, not a live production one.
	void unittestStore()
	{
		assertNotThrown( this.wipeEverythingAndInit() );
		assert( this.getUserCount() == 0 );
		
		assertNotThrown!UserAlreadyExistsException( this.createUser("Mo",  dupPassword("stuffjunk")) );
		assertNotThrown!UserAlreadyExistsException( this.createUser("Joe", dupPassword("pass123"  )) );
		assertNotThrown!UserAlreadyExistsException( this.createUser("Cho", dupPassword("test pass")) );

		assert( this.getUserCount() == 3 );
		assert( this.userExists("Mo")  );
		assert( this.userExists("Joe") );
		assert( this.userExists("Cho") );
		assert( !this.userExists("Herman") );
		assert( !this.userExists("") );
		
		assertNotThrown!UserNotFoundException( this.removeUser("Mo") );

		assert( this.getUserCount() == 2 );
		assert( !this.userExists("Mo") );
		assert( this.userExists("Joe") );
		assert( this.userExists("Cho") );
		
		assertThrown!UserNotFoundException( this.removeUser("Mo") );
		assertThrown!UserNotFoundException( this.removeUser("Herman") );

		assert( this.getUserCount() == 2 );
		assert( !this.userExists("Mo") );
		assert( this.userExists("Joe") );
		assert( this.userExists("Cho") );
		
		assert( this.validateUser ("Joe",    dupPassword("pass123")) );
		assert( !this.validateUser("Cho",    dupPassword("pass123")) );
		assert( !this.validateUser("Herman", dupPassword("pass123")) );

		assert( !this.validateUser("Joe",    dupPassword("test pass")) );
		assert( this.validateUser ("Cho",    dupPassword("test pass")) );
		assert( !this.validateUser("Herman", dupPassword("test pass")) );
		
		assertNotThrown!UserNotFoundException( this.modifyUser("Cho", dupPassword("pass123")) );
		assert( this.validateUser ("Cho", dupPassword("pass123"  )) );
		assert( !this.validateUser("Cho", dupPassword("test pass")) );
		
		assert( this.store.getHash("Joe").toString() != this.store.getHash("Cho").toString() );

		assert( this.getUserCount() == 2 );
		assertNotThrown( this.wipeEverythingAndInit() );
		assert( this.getUserCount() == 0 );
		assertNotThrown( this.store.wipeEverything() );
		
		// Should not fail even if already wiped
		assertNotThrown( this.store.wipeEverything() );
	}
}
