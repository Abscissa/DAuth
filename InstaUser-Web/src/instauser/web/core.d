/// InstaUser-Web
/// Core module

module instauser.web.core;

import vibe.vibe;
import semitwistWeb.form;
import semitwistWeb.handler;
import instauser.store;


version(InstaUserWeb_Unittest)
unittest
{
	import std.stdio;
	writeln("In InstaUserWeb unittest");
}


//import semitwistWeb.packageVersion;
//pragma(msg, "semitwistWeb: "~semitwistWeb.packageVersion.packageVersion);
