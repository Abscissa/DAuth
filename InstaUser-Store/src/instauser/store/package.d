/++
InstaUser-Store - User Account Library for D

Writen in the D programming language.
Tested with DMD 2.065
Licensed under The zlib/libpng License

Homepage:
$(LINK https://github.com/abscissa/InstaUser-Store)

Uses $(LINK2 https://github.com/abscissa/DAuth,DAuth)

Author: Nick Sabalausky

DMD flags to enable InstaUser-Store unittests:
	-unittest -version=InstaUserStore_Unittest -version=Have_mysql_native

Add this to silence all non-error output in InstaUser-Store unittests:
	-version=InstaUserStore_Unittest_Quiet

Modules:
$(LINK2 store/core.html,instauser.store.core)$(BR)
$(LINK2 store/storage/memory.html,instauser.store.storage.memory)$(BR)
$(LINK2 store/storage/mysqln.html,instauser.store.storage.mysqln)$(BR)
+/

module instauser.store;

public import instauser.store.core;
public import instauser.store.storage.memory;
version(Have_mysql_native)
	public import instauser.store.storage.mysqln;
