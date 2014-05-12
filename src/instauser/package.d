/++
InstaUser - User Account Library for D

Writen in the D programming language.
Tested with DMD 2.065
Licensed under The zlib/libpng License

Homepage:
$(LINK https://github.com/abscissa/InstaUser)

Uses $(LINK2 https://github.com/abscissa/DAuth,DAuth)

Author: Nick Sabalausky
+/

module instauser;

public import instauser.core;
public import instauser.store.memory;
version(Have_mysqln)
	public import instauser.store.mysqln;
