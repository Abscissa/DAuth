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
	
	// An internal helper function for unittests.
	// Outputs a string and flushes stdout. Does nothing if this was
	// compiled with -version=InstaUser_Unittest_Quiet.
	void unitlog(string str)
	{
		version(Loud_Unittest)
		{
			writeln("unittest InstaUser: ", str);
			stdout.flush();
		}
	}
}

/++
Check if type T is a valid UserStore. The store must accept password hashes
which use OO-style Digest and optionally another digest type TDigest.

A UserStore is any type (typically a class) which implements the following
public functions:

---------------
/// Create a new user, returning false if user already exists.
bool create(string name, Hash!SomeDigest hash);

/// Change a user's password, returning false if user doesn't exist.
bool modify(string name, Hash!SomeDigest hash);

/// Retreive a user's password hash, returning null if user doesn't exist.
NullableHash!std.digest.digest.Digest getHash(string name);

/// Permanently delete a user.
bool remove(string name);

/// PERMANENTLY DELETES ALL user data in the store.
void wipeEverything();

/// Initialize a new store. The store is assumed to have already been wiped,
/// or have never previously existed.
void init();
---------------

Where SomeDigest can be any Phobos-compatible digest. The create/modify
functions MUST accept the OO-style std.digest.digest.Digest. They SHOULD also
accept any OO-style or template-style digest that satisfies isAnyDigest, but
are not required to.

Optionally, a UserStore may also implement this function (is so, the UserStore
will satisfy the optional hasGetUserCount):

---------------
/// Retrive number of users in the store.
ulong getUserCount();
---------------
+/
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

/++
Tests whether type T offers the following function:

---------------
/// Retrive number of users in the store.
ulong getUserCount();
---------------

Type T is NOT required to be a valid UserStore.
+/
enum hasGetUserCount(T) = is(typeof((){
	T t;
	ulong x = t.getUserCount();
}));

/// Convenience alias for Nullable!(Hash!TDigest)
alias NullableHash(TDigest) = Nullable!(Hash!TDigest);

/// Thrown by InstaUser.createUser when trying to create a user that already exists.
class UserAlreadyExistsException : Exception
{
	string name;
	
	this(string name)
	{
		this.name = name;
		super("User already exists: "~name);
	}
}

/// Thrown by InstaUser.modifyUser and InstaUser.removeUser when the specified
/// user doesn't exist.
class UserNotFoundException : Exception
{
	string name;

	this(string name)
	{
		this.name = name;
		super("User not found: "~name);
	}
}

/// The main interface for the InstaUser library.
///
/// Construct this with any UserStore and then create/validate/modify/delete
/// users as desired. Passwords will automatically be hashed with random salts
/// via $(LINK2 https://github.com/abscissa/DAuth, DAuth).
struct InstaUser(Store)
{
	Store store;
	
	/// Constructor. Pass in any desired UserStore.
	this(Store store)
	{
		this.store = store;
	}
	
	/++
	Creates a new user with a given
	$(LINK2 http://semitwist.com/dauth/core.html#Password, Password).
	
	The password is automatically hashed with a random salt.
	
	Throws UserAlreadyExistsException if the user already exists.
	+/
	void createUser(TDigest = DefaultDigest)
		(string name, Password pass)
		if(isUserStore!(Store, TDigest))
	{
		if(!store.create(name, makeHash(pass)))
			throw new UserAlreadyExistsException(name);
	}

	/++
	Changes a user's $(LINK2 http://semitwist.com/dauth/core.html#Password, Password).
	
	The password is automatically hashed with a random salt.
	
	Throws UserNotFoundException if the user doesn't exist.
	+/
	void modifyUser(TDigest = DefaultDigest)
		(string name, Password pass)
		if(isUserStore!(Store, TDigest))
	{
		auto hash = makeHash(pass);

		if(!store.modify(name, hash))
			throw new UserNotFoundException(name);
	}

	/++
	Permanently deletes a user.
	
	Throws UserNotFoundException if the user doesn't exist.
	+/
	void removeUser(string name)
	{
		if(!store.remove(name))
			throw new UserNotFoundException(name);
	}

	/++
	Checks whether the provided $(LINK2 http://semitwist.com/dauth/core.html#Password, Password)
	matches the user's password.
	
	Returns false if the password hashes don't match OR if the user doesn't exist.
	
	To thwart timing attacks, password hashes are compared using length-constant comparisons .
	+/
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

	/// Checks whether the user exists
	bool userExists(string name)
	{
		return !store.getHash(name).isNull();
	}

	/// Retreives the number of users in the store.
	///
	/// To use this, the store must satisfy hasGetUserCount. Otherwise,
	/// this function will be disallowed at compile-time.
	ulong getUserCount()() if(hasGetUserCount!Store)
	{
		return store.getUserCount();
	}

	/// PERMANENTLY DELETES ALL user data in the store and re-initializes
	/// the store to a fresh empty state. This automatically calls the store's
	/// wipeEverything and init functions.
	void wipeEverythingAndInit()
	{
		store.wipeEverything();
		store.init();
	}
	
	/// Run standard set of tests on an InstaUser user store.
	///
	/// This will PERMANENTLY DELETE ALL data in the store, so only use it
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
