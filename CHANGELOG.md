DAuth - Changelog
=================

(Dates below are YYYY/MM/DD)

v0.6.1 - TBD - crypt(3)
-------------------
- **Enhancement:** Added support for [crypt(3)](https://en.wikipedia.org/wiki/Crypt_(C))-style hash strings. Currently supports ```$1$``` (MD5), ```$5$``` (SHA-256) and ```$6$``` (SHA-512).
- **Change:** Removed ```dauth.hashdrbg.isSomeStream``` because it's named wrong, unused, and not particularly useful anyway.

v0.6.0 - 2014/05/22 - SHA-2, Hash_DRBG and Separate Modules
-------------------
- **Enhancement:** Added cryptographically secure hash/digest algorithm [SHA-2](http://en.wikipedia.org/wiki/Sha2). Note: DAuth is only a temporary home for SHA-2 until it's [added to Phobos](https://github.com/D-Programming-Language/phobos/pull/2129))
- **Enhancement:** Added cryptographic random number generator [Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf) and OS-native random number generation. Note: DAuth is may only be a temporary home for these. A pull request for std.random will be made.
- **Enhancement:** Added this changelog.
- **Change:** Default digest upgraded from [SHA-1](http://en.wikipedia.org/wiki/SHA-1) to [SHA-512](http://en.wikipedia.org/wiki/Sha2).
- **Change:** Default random number generator upgraded from [Mt19937](http://dlang.org/phobos/std_random.html#Mt19937) to [Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf) using SHA-512.
- **Change:** Change callbacks from function to delegate.
- **Change:** Split DAuth into separate modules (maintaining support for ```import dauth;``` via package.d).
- **Fixed:** Blindly accepted (unsupported) non-uint random number ranges instead of rejecting them with constraints.
- **Fixed:** Calling ```isPasswordCorrect(Password, Hash!Digest)``` fails with ugly compile error.
- **Fixed:** ```dub.json``` broken, wrong format for ```sourcePaths``` and ```importPaths```.

v0.5.1 - 2014/04/06
-------------------
- **Fixed:** [DUB](http://code.dlang.org/) package names must be all-lowercase.

v0.5.0 - 2014/04/06
-------------------
- Initial release
