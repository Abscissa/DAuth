/// InstaUser - User Account Library for D
/// Data Store: MySQL-native
///
/// Main module: $(LINK2 index.html,instauser)$(BR)

module instauser.store.mysqln;

version(Have_mysqln) {} else
	static assert(false, "Module instauser.store.mysqln requires -version=Have_mysqln");

import std.conv;
import std.digest.digest;
import std.exception	;
import mysql.connection;
import mysql.db;

import dauth.core;
import instauser.core;

/// Less confusing name for a MySQL connection.
alias MySQLConnection = mysql.connection.Connection;

version(Have_vibe_d)
{
	/// Less confusing name for a Vibe.d MySQL connection pool.
	///
	/// Normally, this is set to mysql.db.MysqlDB. But if Vibe.d isn't
	/// compiled in, it's set to a dummy type.
	alias MySQLConnectionPool = mysql.db.MysqlDB;
}
else
{
	private struct Dummy_PoolRequiresVibeD {}

	/// Less confusing name for a Vibe.d MySQL connection pool.
	///
	/// Normally, this is set to mysql.db.MysqlDB. But if Vibe.d isn't
	/// compiled in, it's set to a dummy type.
	alias MySQLConnectionPool = Dummy_PoolRequiresVibeD;
}

private enum MySQLErrorCode
{
	DuplicateEntry = 1062,
}

/// If Conn is a MySQLConnection, then the user of this class is responsible
/// for opening/closing the connection.
class MySQLNativeStore(Conn) if(is(Conn == MySQLConnection) || is(Conn == MySQLConnectionPool))
{
	version(Have_vibe_d) {} else
	{
		static assert(
			!is(Conn == MySQLConnectionPool),
			"MySQLConnectionPool requires Vibe.d and -version=Have_vibe_d"
		);
	}
	
	Conn conn;
	protected string table;
	protected string nameField;
	protected string passField;
	
	/++
	conn: The MySQLConnection or MySQLConnectionPool to use.
	table: Name of the DB table to use.
	nameField: Name of the DB field/column for storing the user names.
	passField: Name of the DB field/column for storing the salted password hashes.
	+/
	this(Conn conn, string table = "users", string nameField = "name", string passField = "pass")
	{
		//TODO: Ban table/field names that have whitespace or backticks
		this.conn = conn;
		this.table = table;
		this.nameField = nameField;
		this.passField = passField;
	}
	
	protected MySQLConnection lockConn()
	{
		static if(is(Conn == MySQLConnectionPool))
			return conn.lockConnection();
		else
			return conn;
	}
	
	///
	bool create(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		static string sql = null;
		if(!sql)
			sql = "INSERT INTO `"~table~"` (`"~nameField~"`, `"~passField~"`) VALUES (?, ?)";

		auto cmd = Command(lockConn());
		cmd.sql = sql;
		cmd.prepare();
		auto hashStr = hash.toString();
		cmd.bindParameterTuple(name, hashStr);

		ulong rowsAffected;
		try
			cmd.execPrepared(rowsAffected);
		catch(MySQLReceivedException e)
		{
			if(e.errorCode == MySQLErrorCode.DuplicateEntry)
				return false;
			
			throw e;
		}
		
		return true;
	}
	
	///
	bool modify(TDigest)(string name, Hash!TDigest hash) if(isAnyDigest!TDigest)
	{
		static string sql = null;
		if(!sql)
			sql = "UPDATE `"~table~"` SET `"~passField~"`=? WHERE `"~nameField~"`=?";

		auto cmd = Command(lockConn());
		cmd.sql = sql;
		cmd.prepare();
		auto hashStr = hash.toString();
		cmd.bindParameterTuple(hashStr, name);

		ulong rowsAffected;
		cmd.execPrepared(rowsAffected);
		
		enforce(rowsAffected < 2,
			"Password was changed on "~to!string(rowsAffected)~" user rows, not just one. "~
			"User name: "~name~"\n"~
			"Constraints on table `"~table~"` are probably not set up properly.");
		return rowsAffected != 0;
	}
	
	///
	NullableHash!Digest getHash(string name)
	{
		static string sql = null;
		if(!sql)
			sql = "SELECT `"~passField~"` FROM `"~table~"` WHERE `"~nameField~"`=?";

		auto cmd = Command(lockConn());
		cmd.sql = sql;
		cmd.prepare();
		cmd.bindParameterTuple(name);

		auto results = cmd.execPreparedResult();
		
		enforce(results.length < 2,
			"Received hashed password field for "~to!string(results.length)~" user rows, not just one. "~
			"User name: "~name~"\n"~
			"Constraints on table `"~table~"` are probably not set up properly.");
		
		if(results.length == 0)
			return NullableHash!Digest();

		return NullableHash!Digest( parseHash(results[0][0].toString()) );
	}
	
	///
	bool remove(string name)
	{
		static string sql = null;
		if(!sql)
			sql = "DELETE FROM `"~table~"` WHERE `"~nameField~"`=?";

		auto cmd = Command(lockConn());
		cmd.sql = sql;
		cmd.prepare();
		cmd.bindParameterTuple(name);

		ulong rowsAffected;
		cmd.execPrepared(rowsAffected);
		
		enforce(rowsAffected < 2,
			"Deleted "~to!string(rowsAffected)~" user rows, not just one. "~
			"User name: "~name~"\n"~
			"Constraints on table `"~table~"` are probably not set up properly.");
		return rowsAffected != 0;
	}
	
	///
	ulong getUserCount()
	{
		static string sql = null;
		if(!sql)
			sql = "SELECT COUNT(*) FROM `"~table~"`";

		auto cmd = Command(lockConn());
		cmd.sql = sql;
		auto results = cmd.execSQLResult();
		
		enforce(results.length == 1,
			"Error retreiving user count. Expected 1 row, got "~to!string(results.length));
		
		auto userCount = results[0][0].coerce!long();
		enforce(userCount >= 0, "Received negative user count: "~to!string(userCount));
		return cast(ulong)userCount;
	}
	
	///
	void wipeEverything()
	{
		static string sql = null;
		if(!sql)
			sql = "DROP TABLE IF EXISTS `"~table~"`";
		
		auto cmd = Command(lockConn());
		ulong rowsAffected;
		cmd.sql = sql;
		cmd.execSQL(rowsAffected);
	}
	
	///
	void init()
	{
		static string sql = null;
		if(!sql)
		{
			sql =
				"CREATE TABLE `"~table~"` (
				`"~nameField~"` varchar(255) NOT NULL,
				`"~passField~"` varchar(255) NOT NULL,
				PRIMARY KEY  (`"~nameField~"`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8";
		}
		
		auto cmd = Command(lockConn());
		ulong rowsAffected;
		cmd.sql = sql;
		cmd.execSQL(rowsAffected);
	}
}

version(InstaUser_Unittest)
unittest
{
	unitlog("Testing MySQLNativeStore!MySQLConnection");

	static assert(isUserStore!(MySQLNativeStore!MySQLConnection));
	static assert(hasGetUserCount!(MySQLNativeStore!MySQLConnection));
	version(Have_vibe_d)
	{
		static assert(isUserStore!(MySQLNativeStore!MySQLConnectionPool));
		static assert(hasGetUserCount!(MySQLNativeStore!MySQLConnectionPool));
	}

	auto connStr = "host=localhost;port=3306;user=instauser_test;pwd=pass123;db=instauser_testdb";
	auto store = new MySQLNativeStore!MySQLConnection(new MySQLConnection(connStr));
	scope(exit) store.conn.close();
	
	auto instaUser = InstaUser!(MySQLNativeStore!MySQLConnection)(store);

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
