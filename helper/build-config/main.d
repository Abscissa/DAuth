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

import scriptlike;

enum configLibrary = "library";
enum configTests   = "tests";
enum configDocs    = "docs";
immutable allConfigs = [configLibrary, configTests, configDocs];

enum subProjectBasic = "basic";
enum subProjectStore = "store";
enum subProjectWeb   = "web";
immutable allSubProjects = [subProjectBasic, subProjectStore, subProjectWeb];

void main(string[] args)
{
	// Check args
	if(args.length != 7)
	{
		fail(
			"Wrong number args\n",
			"Usage:",
			" dub run -- $DUB_CONFIG (basic|store|web) $PACKAGE_DIR",
			" $SAFEARG_PACKAGE_DIR $DDOX_PACKAGE_DIR $ROOT_PACKAGE_DIR"
		);
	}
	
	// Get args
	const configName     = args[1];
	const subProjectName = args[2];
	auto  packageDir     = Path(args[3]);
	auto  safeArgDir     = Path(args[4]);
	auto  ddoxDir        = Path(args[5]);
	auto  rootPackageDir = Path(args[6]);
	auto  safeArgTool = safeArgDir ~ "bin/safearg";

	// Set working dir to correct subproject
	chdir(packageDir);
	
	// Validate configName
	if(!canFind(allConfigs, configName))
		fail("Invalid config '", configName, "'. Expected one of these: ", allConfigs);
	
	// Validate subProjectName
	if(!canFind(allSubProjects, subProjectName))
		fail("Invalid subproject '", subProjectName, "'. Expected one of these: ", allSubProjects);
	
	// If test/docs mode, only run this script for the requested subproject.
	if(configName == configTests || configName == configDocs)
	{
		// This script gets run as a postBuildCommand, so the InstaUser subpackage
		// in question MIGHT NOT be the root project actually being built.
		//
		// So, don't run the tests or build docs unless this actually IS the root project.
		if(packageDir != rootPackageDir)
			return;
	}
	
	// Only build docs for InstaUser-Web, because that will
	// automatically include the docs for the rest of InstaUser.
	if(configName == configDocs && subProjectName != subProjectWeb)
	{
		writeln("Not building docs for instauser-", subProjectName, ".");
		writeln(
			"Please build the docs for instauser-web instead, ",
			"that will automatically include the docs for all of InstaUser."
		);
		return;
	}
	
	// Ensure safearg is built
	run(safeArgDir, "dub build");

	// Build config: library
	if(configName == configLibrary)
	{
		// Generate commands
		version(Posix)        const libName = "libinstauser-"~subProjectName~".a";
		else version(Windows) const libName = "instauser-"~subProjectName~".lib";
		else static assert(0);

		const libPath = packageDir ~ "lib" ~ libName;

		const dubDescribeDataCmd =
			"dub describe --nodeps --compiler=dmd --config=library --data-0 "~
			"--data=options,versions,import-paths";

		const rdmdCmd =
			"rdmd --build-only -lib -Ires -Jres -od. -of"~libPath.toRawString()~" --force";

		const safeArgToRdmdCmd =
			safeArgTool.toString()~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;
		
		// Compile/Run tests
		writeln("Compiling instauser-", subProjectName, " library...");
		run(packageDir, dubDescribeDataCmd~" | "~safeArgToRdmdCmd);

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
			safeArgTool.toString()~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;
		
		// Compile/Run tests
		writeln("Compiling/Running instauser-", subProjectName, " tests...");
		run(packageDir, dubDescribeDataCmd~" | "~safeArgToRdmdCmd);
	}

	// Build config: docs
	else if(configName == configDocs)
	{
		// Ensure ddox is built
		run(ddoxDir, "dub build");

		// Generate commands
		const dubDescribeDataCmd =
			"dub describe --nodeps --compiler=dmd --config=tests --data-0 "~
			"--data=versions,import-paths,string-import-paths";

		const rdmdCmd =  // For some reason, '--exclude=mustache' has no effect. No idea why. So just exclude it in 'ddox filter' below.
			"rdmd --build-only --force -c -Dddocs_tmp -X -Xf../docs/docs.json "~
			"--exclude=vibe --exclude=deimos --exclude=mysql --exclude=arsd "~
			"--exclude=mustache --exclude=semitwist --exclude=semitwistWeb";

		const safeArgToRdmdCmd =
			safeArgTool.toString()~" --post=src/instauser/"~subProjectName~"/package.d "~rdmdCmd;

		// Generate doc information
		writeln("Generating InstaUser docs...");
		//writeln("Generating instauser-", subProjectName, " docs...");
		run(packageDir, dubDescribeDataCmd~" | "~safeArgToRdmdCmd);
		
		// Delete junk
		rmdirRecurse("docs_tmp");
		version(Posix)        std.file.remove("src/instauser/"~subProjectName~"/package");
		else version(Windows) std.file.remove("src/instauser/"~subProjectName~"/package.exe");
		else static assert(0);
		
		// Pass though DDOX to generate docs
		auto ddoxTool = ddoxDir ~ "ddox";
		run(packageDir, ddoxTool.toString()~" filter ../docs/docs.json --min-protection=Protected --ex=mustache");
		run(packageDir, ddoxTool.toString()~" generate-html ../docs/docs.json ../docs/public --navigation-type=ModuleTree");

		// Done
		writeln("To view InstaUser docs, open this file in your web browser:");
		writeln(buildNormalizedPath(absolutePath("../docs/public/index.html")));
	}
}
