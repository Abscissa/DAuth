/++
Homepage:
$(LINK https://github.com/Abscissa/InstaUser)

This_API_Reference:
$(LINK http://semitwist.com/instauser)

Import_all:
------------
import instauser.basic;
------------
+/

module instauser.basic;

public import instauser.basic.core;
public import instauser.basic.hashdrbg;
public import instauser.basic.random;

version(InstaUserBasic_Unittest)
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

version(InstaUserBasic_Unittest)
	void main() {}
