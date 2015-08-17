/// IMPORTANT!
///
/// Make a copy of this file named 'conf.d'
/// with the values below filled in.
///
/// If you change this file, you will need to recompile.

/++
Examples for host and urlBase:
- If this program is setup to be publically accessed via:
     http://mydomain.com

  Then the settings should be:
     host:    http://mydomain.com
     urlBase: /

- If this program is setup to be publically accessed via:
     https://mydomain.com:8181/my/cool/stuff

  Then the settings should be:
     host:    https://mydomain.com:8181
     urlBase: /my/cool/stuff/

Note:
host: Must OMIT trailing slash.
urlBase: Must INCLUDE leading AND trailing slash.
+/
immutable host = `https://localhost:8080`;
immutable urlBase = `/`;

/++
'staticsRealPath':    Must be relative to the executable.
'staticsVirtualPath': Must be relative to 'urlBase'.

TODO: NOT YET: 'staticsRealPath':    Either absolute, or relative to the executable.
TODO: NOT YET: 'staticsVirtualPath': Either absolute, or relative to 'urlBase'. Can also
be a full http:// or https:// URL.

Both must INCLUDE a trailing slash.
+/
immutable staticsRealPath    = `../www-static/`;
immutable staticsVirtualPath = `static/`;

/// DB Connection Settings
/// Must have permissions for: SELECT, INSERT, UPDATE, DELETE
/// When initing the DB, you must also have permissions for: CREATE, DROP
immutable dbHost = "127.0.0.1";
immutable dbPort = 3306;
immutable dbUser = "username";
immutable dbPass = "password";
immutable dbName = "database-name";

/// SMTP Settings
import vibe.mail.smtp;
immutable smtpAuthType       = SMTPAuthType.plain;
immutable smtpConnectionType = SMTPConnectionType.startTLS;
immutable smtpHost      = "example.com";
//immutable smtpLocalName = "";
immutable smtpPort      = 25;
immutable smtpUser      = "notifier@example.com";
immutable smtpPass      = "password";
