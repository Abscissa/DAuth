import std.algorithm;
import std.exception;
import std.file;
import std.path;
import std.process;
import std.range;
import std.stdio;

int main(string[] args)
{
	// Check args
	if(args.length != 6)
	{
		stderr.writeln(
			"Usage:"
			" rdmd ../helper/build_tests.d (basic|store|web) $PACKAGE_DIR",
			" $SAFEARG_PACKAGE_DIR $DDOX_PACKAGE_DIR $ROOT_PACKAGE_DIR"
		);
		return 1;
	}
	
	// Get args
	const subProjectName = args[1];
	const packageDir     = args[2];
	const safeArgDir     = args[3];
	const ddoxDir        = args[4];
	const rootPackageDir = args[5];
	
	// This script gets run as a postBuildCommand, so the InstaUser subpackage
	// in question MIGHT NOT be the root project actually being built.
	//
	// So, don't run the tests unless this actually IS the root project.
	if(packageDir != rootPackageDir)
		return 0;
	
	// Save current working dir
	immutable origWorkingDir = getcwd();
	scope(exit) chdir(origWorkingDir);
	
	// Ensure safearg is built
	chdir(safeArgDir);
	spawnShell("dub build").wait();
	
	// Build commands
	version(Posix) enum extraArgs = " -L-levent_pthreads -L-levent -L-lssl -L-lcrypto";
	else           enum extraArgs = "";

	const safeArgTool = escapeShellFileName( buildNormalizedPath(safeArgDir, "bin/safearg") );

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
	
	return 0;
}
