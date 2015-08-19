/++
This script is invoked by dub.sdl's postBuildCommands.

This does the actual building (instead of DUB) for each
of the available configurations, by invoking rdmd.

Most of the arguments to be passed into rdmd, such as
import paths, are obtained by invoking:
	dub describe --data-0 --data=...
And piping the result through safeArg[1] into rdmd.

[1]safeArg: https://github.com/Abscissa/safeArg
+/

import std.algorithm;
import std.exception;
import std.file;
import std.path;
import std.process;
import std.range;
import std.stdio;

enum configLibrary = "library";
enum configTests   = "tests";
enum configDocs    = "docs";
immutable allConfigs = [configLibrary, configTests, configDocs];

int main(string[] args)
{
	// Check args
	if(args.length != 7)
	{
		stderr.writeln(
			"Wrong number args\n",
			"Usage:",
			" rdmd ../helper/build.d $DUB_CONFIG (basic|store|web) $PACKAGE_DIR",
			" $SAFEARG_PACKAGE_DIR $DDOX_PACKAGE_DIR $ROOT_PACKAGE_DIR"
		);
		return 1;
	}
	
	// Get args
	const configName     = args[1];
	const subProjectName = args[2];
	const packageDir     = args[3];
	const safeArgDir     = args[4];
	const ddoxDir        = args[5];
	const rootPackageDir = args[6];
	const safeArgTool = escapeShellFileName( buildNormalizedPath(safeArgDir, "bin/safearg") );
	
	// Validate configName
	if(!canFind(allConfigs, configName))
	{
		stderr.writeln("Invalid config '", configName, "'. Expected one of these: ", allConfigs);
		return 1;
	}
	
	// If test mode, only run tests for the requested subproject.
	if(configName == configTests)
	{
		// This script gets run as a postBuildCommand, so the InstaUser subpackage
		// in question MIGHT NOT be the root project actually being built.
		//
		// So, don't run the tests unless this actually IS the root project.
		if(packageDir != rootPackageDir)
			return 0;
	}
	
	// Save current working dir
	immutable origWorkingDir = getcwd();
	scope(exit) chdir(origWorkingDir);
	
	// Ensure safearg is built
	chdir(safeArgDir);
	spawnShell("dub build").wait();

	// Build config: library
	if(configName == configLibrary)
	{
		// Generate commands
		version(Posix)        const libName = "libinstauser-"~subProjectName~".a";
		else version(Windows) const libName = "instauser-"~subProjectName~".lib";
		else static assert(0);

		const dubDescribeDataCmd =
			"dub describe --nodeps --compiler=dmd --config=library --data-0 "~
			"--data=options,versions,import-paths";

		const rdmdCmd =
			"rdmd --build-only -lib -Ires -Jres -od. -of"~packageDir~"lib/"~libName~" --force";

		const safeArgToRdmdCmd =
			safeArgTool~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;
		
		// Compile/Run tests
		writeln("Compiling instauser-", subProjectName, " library...");
		chdir(packageDir);
		spawnShell(dubDescribeDataCmd~" | "~safeArgToRdmdCmd).wait();

		// Delete junk
		version(Posix)        std.file.remove("package.a");
		else version(Windows) std.file.remove("package.obj");
		else static assert(0);
	}

	// Build config: tests
	else if(configName == configTests)
	{
		// Generate commands
		version(Posix)        enum extraArgs = " -L-levent_pthreads -L-levent -L-lssl -L-lcrypto";
		else version(Windows) enum extraArgs = "";
		else static assert(0);

		const dubDescribeDataCmd =
			"dub describe --nodeps --compiler=dmd --config=tests --data-0 "~
			"--data=options,versions,import-paths,linker-files";

		const rdmdCmd =
			"rdmd -Ires -Jres -ofbin/instauser-"~subProjectName~"-unittest "~
			"-debug -g -unittest -main --force"~extraArgs;

		const safeArgToRdmdCmd =
			safeArgTool~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;
		
		// Compile/Run tests
		writeln("Compiling/Running instauser-", subProjectName, " tests...");
		chdir(packageDir);
		spawnShell(dubDescribeDataCmd~" | "~safeArgToRdmdCmd).wait();
	}

	// Build config: docs
	else if(configName == configDocs)
	{
		// Ensure ddox is built
		chdir(ddoxDir);
		spawnShell("dub build").wait();

		// Generate commands
		const dubDescribeDataCmd =
			"dub describe --nodeps --compiler=dmd --config=tests --data-0 "~
			"--data=versions,import-paths,string-import-paths";

		const rdmdCmd =  // For some reason, '--exclude=mustache' has no effect. No idea why. So just exclude it in 'ddox filter' below.
			"rdmd --chatty --build-only --force -c -Dddocs_tmp -X -Xfdocs/docs.json "~
			"--exclude=vibe --exclude=deimos --exclude=mysql --exclude=arsd "~
			"--exclude=mustache --exclude=semitwist --exclude=semitwistWeb";

		const safeArgToRdmdCmd =
			safeArgTool~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;

		// Generate doc information
		writeln("Generating instauser-", subProjectName, " docs...");
		chdir(packageDir);
		spawnShell(dubDescribeDataCmd~" | "~safeArgToRdmdCmd).wait();
		
		// Delete junk
		rmdirRecurse("docs_tmp");
		version(Posix)        std.file.remove("src/instauser/"~subProjectName~"/package");
		else version(Windows) std.file.remove("src/instauser/"~subProjectName~"/package.exe");
		else static assert(0);
		
		// Pass though DDOX to generate docs
		spawnShell(ddoxDir~dirSeparator~"ddox filter docs/docs.json --min-protection=Protected --ex=mustache").wait();
		spawnShell(ddoxDir~dirSeparator~"ddox generate-html docs/docs.json docs/public --navigation-type=ModuleTree").wait();
	}
	
	return 0;
}
