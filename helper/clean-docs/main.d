import scriptlike;

void main()
{
	const docsDir = thisExePath().dirName() ~ "../../docs";
	//writeln("docsDir: ", docsDir);
	chdir(docsDir);
	tryRemove(Path("docs.json"));
	tryRemove(Path("public/file_hashes.json"));
	tryRemove(Path("public/index.html"));
	tryRemove(Path("public/sitemap.xml"));
	tryRemove(Path("public/symbols.js"));
	tryRmdirRecurse(Path("public/instauser"));
}
