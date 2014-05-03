/++
DAuth v0.5.1 - Authentication Utility for D

Writen in the D programming language.
Tested with DMD 2.064.2 and 2.065
Licensed under The zlib/libpng License

Homepage:
$(LINK https://github.com/abscissa/DAuth)

This API Reference:
$(LINK http://semitwist.com/dauth)

Author: Nick Sabalausky

DMD flags to enable DAuth unittests:
	-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest

DMD flags to enable DAuth unittests, but silence all non-error output:
	-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest -version=DAuth_Unittest_Quiet

Note that dauth.sha is not automatically included by "import dauth;" and must
be imported separately. This is because it's only in DAuth temporarily, until
SHA-2 is in Phobos: $(LINK https://github.com/D-Programming-Language/phobos/pull/2129)

Import all:
------------
import dauth;
import dauth.sha;
------------

Modules:
$(LINK2 core.html,dauth.core)$(BR)
$(LINK2 random.html,dauth.random)$(BR)
$(LINK2 sha.html,dauth.sha)$(BR)
+/

module dauth;

public import dauth.core;
public import dauth.random;

version(DAuth_Unittest)
	import dauth.sha;
