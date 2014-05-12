/// InstaUser - User Account Library for D
/// Data Store: MySQL-native
///
/// Main module: $(LINK2 index.html,instauser)$(BR)

module instauser.store.mysqln;

version(Have_mysqln) {} else
	static assert(false, "Module instauser.store.mysqln requires -version=Have_mysqln");


