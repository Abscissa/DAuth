/++
DAuth v0.6.1 - Salted Hashed Password Library for D

Writen in the D programming language.

Tested with DMD 2.064.2 through DMD 2.066

Homepage:
$(LINK https://github.com/abscissa/DAuth)

This_API_Reference:
$(LINK http://semitwist.com/dauth)

DMD flags to enable DAuth unittests:
-------------------
-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest
-------------------

DMD flags to enable DAuth unittests, but silence all non-error output:
-------------------
-unittest -version=DAuth_AllowWeakSecurity -version=DAuth_Unittest -version=DAuth_Unittest_Quiet
-------------------

Note that dauth.sha is not automatically included by "import dauth;" and must
be imported separately. This is because it's only in DAuth temporarily (until
SHA-2 is in Phobos). On compilers where SHA-2 exists in Phobos (ie, DMD 2.066
and up), then DAuth does NOT use dauth.sha.

The module dauth.hashdrbg is also excluded by default because a Phobos pull request
is in the works.

Import all:
------------
import dauth;
import dauth.sha;
import dauth.hashdrbg;
------------

Copyright: © 2014 Nick Sabalausky
License: zlib/libpng license, provided in
	$(LINK2 LICENSE.txt, https://github.com/Abscissa/DAuth/blob/master/LICENSE.txt).
Authors: Nick Sabalausky
+/

module dauth;

public import dauth.core;
public import dauth.random;

version(DAuth_Unittest)
{
	import dauth.sha;
	import dauth.hashdrbg;
}
