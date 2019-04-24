/++
DAuth v0.6.2 - Salted Hashed Password Library for D

Writen in the D programming language.

Tested with DMD 2.064.2 through DMD 2.067.0

Homepage:
$(LINK https://github.com/abscissa/DAuth)

This_API_Reference:
$(LINK http://semitwist.com/dauth)

DMD flags to enable DAuth unittests:
-------------------
-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest
-------------------

DMD flags to enable DAuth unittests, but silence all non-error output:
-------------------
-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest -version=DAuth_Unittest_Quiet
-------------------

The module dauth.hashdrbg is also excluded by default because a Phobos pull request
is in the works.

Import all:
------------
import dauth;
import dauth.hashdrbg;
------------

Copyright: © 2014 Nick Sabalausky
License: zlib/libpng license, provided in
	$(LINK2 LICENSE.txt, https://github.com/Abscissa/DAuth/blob/master/LICENSE.txt).
Authors: Nick Sabalausky
+/

module dauth;

public import dauth.core;
public import dauth.random;

version(DAuth_Unittest)
{
	import dauth.hashdrbg;

	unittest
	{
		import std.process;

		unitlog("Testing different results on different executions");
		assert(
			spawnShell(`rdmd --build-only --force -Isrc -ofbin/genBytes genBytes.d`).wait()
			== 0, "Failed to compile genBytes.d"
		);
		enum cmd = "bin/genBytes";
		auto result1 = execute(cmd);
		auto result2 = execute(cmd);
		auto result3 = execute(cmd);
		assert(result1.status == 0, "Command failed: "~cmd);
		assert(result2.status == 0, "Command failed: "~cmd);
		assert(result3.status == 0, "Command failed: "~cmd);

		assert(result1.output != result2.output);
		assert(result2.output != result3.output);
		assert(result3.output != result1.output);
	}
}
