import scriptlike;

void main()
{
	const docsDir = thisExePath().dirName()~"../../docs";
	//writeln("docsDir: ", docsDir);
	chdir(docsDir);
	tryRemove("docs.json");
	tryRemove("public/file_hashes.json");
	tryRemove("public/index.html");
	tryRemove("public/sitemap.xml");
	tryRemove("public/symbols.js");
	tryRmdirRecurse("public/instauser");
}
