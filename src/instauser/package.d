/++
InstaUser - User Account Library for D

Writen in the D programming language.
Tested with DMD 2.065
Licensed under The zlib/libpng License

Homepage:
$(LINK https://github.com/abscissa/InstaUser)

Uses $(LINK2 https://github.com/abscissa/DAuth,DAuth)

Author: Nick Sabalausky

DMD flags to enable InstaUser unittests:
	-unittest -version=InstaUser_Unittest -version=Have_mysql_native

Add this to silence all non-error output in InstaUser unittests:
	-version=InstaUser_Unittest_Quiet

Modules:
$(LINK2 core.html,instauser.core)$(BR)
$(LINK2 store/memory.html,instauser.store.memory)$(BR)
$(LINK2 store/mysqln.html,instauser.store.mysqln)$(BR)
+/

module instauser;

public import instauser.core;
public import instauser.store.memory;
version(Have_mysql_native)
	public import instauser.store.mysqln;
