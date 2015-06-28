/++
InstaUser-Basic - Salted Hashed Password Library for D

Writen in the D programming language.

Tested with DMD 2.064.2 through DMD 2.067.0

Homepage:
$(LINK https://github.com/abscissa/InstaUser)

This_API_Reference:
$(LINK http://semitwist.com/dauth)

DMD flags to enable InstaUser-Basic unittests:
-------------------
-unittest -version=InstaUser_AllowWeakSecurity -version=InstaUserBasic_Unittest
-------------------

DMD flags to enable InstaUser-Basic unittests, but silence all non-error output:
-------------------
-unittest -version=InstaUser_AllowWeakSecurity -version=InstaUserBasic_Unittest -version=InstaUserBasic_Unittest_Quiet
-------------------

Note that instauser.basic.sha is not automatically included by
"import instauser.basic;" and must be imported separately. This is because
it's only in InstaUser-Basic temporarily (until SHA-2 is in Phobos). On
compilers where SHA-2 exists in Phobos (ie, DMD 2.066 and up), then InstaUser-Basic
does NOT use instauser.basic.sha.

The module instauser.basic.hashdrbg is also excluded by default because a
Phobos pull request is in the works.

Import all:
------------
import instauser.basic;
import instauser.basic.sha;
import instauser.basic.hashdrbg;
------------

Copyright: © 2014-2015 Nick Sabalausky
License: zlib/libpng license, provided in
	$(LINK2 LICENSE.txt, https://github.com/Abscissa/InstaUser/blob/master/LICENSE.txt).
Authors: Nick Sabalausky
+/

module instauser.basic;

public import instauser.basic.core;
public import instauser.basic.random;

version(InstaUser_Docs)             version = includeEverything;
version(InstaUserBasic_PrebuiltLib) version = includeEverything;
version(InstaUserBasic_Unittest)    version = includeEverything;

version(includeEverything)
{
	import instauser.basic.sha;
	import instauser.basic.hashdrbg;
}
