InstaUser - ChangeLog
=====================

(Dates below are YYYY/MM/DD)

v0.7.0 - TBD
-------------------
- **Change:** Project is now named "InstaUser" instead of "DAuth". What was
once DAuth has now become the first component of InstaUser: "InstaUser-Basic".
- **Change:** Supports DMDFE 2.068.0 through 2.073.2 (see
[.travis.yml](https://github.com/Abscissa/InstaUser/blob/master/.travis.yml)
for list of officially supported compilers).
- **Change**: Perform all builds through [DUB](http://code.dlang.org/getting_started).
- **Change**: Removed built-in SHA module because its SHA2 implementation is
already included in Phobos for all supported compilers.
- **Enhancement:** Tested via [travis.ci](https://travis-ci.org/).

v0.6.3 - 2017/01/31
-------------------
- **Fixed:** [#4](https://github.com/Abscissa/DAuth/issues/4):
Randomness returns same value in separate executions.

v0.6.2 - 2015/03/25
-------------------
- **Fixed:**
[#1](https://github.com/Abscissa/InstaUser/issues/1)/[#2](https://github.com/Abscissa/InstaUser/issues/2):
Compilation failure when using DUB and DMD 2.067 (@NCrashed)

v0.6.1 - 2014/08/30 - Docs and crypt(3) formatting
-------------------
- **Enhancement:** Supports DMD 2.066.0. (Now supports DMD 2.064.2 through 2.066.0.)
- **Enhancement:** Supports [crypt(3)](https://en.wikipedia.org/wiki/Crypt_(C))-style
hash strings. Currently supports ```$1$``` (MD5), ```$5$``` (SHA-256) and ```$6$``` (SHA-512).
- **Enhancement:** Improved [API reference](http://semitwist.com/dauth/) by
using [ddox](https://github.com/rejectedsoftware/ddox).
- **Change:** Rename ```isPasswordCorrect``` to ```isSameHash```. Old name
temporarily maintained as an alias.
- **Change:** Removed ```dauth.hashdrbg.isSomeStream``` because it's named
 wrong, unused, and not particularly useful anyway.

v0.6.0 - 2014/05/22 - SHA-2, Hash_DRBG and Separate Modules
-------------------
- **Enhancement:** Added cryptographically secure hash/digest algorithm
[SHA-2](http://en.wikipedia.org/wiki/Sha2). Note: DAuth is only a temporary
home for SHA-2 until it's
[added to Phobos](https://github.com/D-Programming-Language/phobos/pull/2129))
- **Enhancement:** Added cryptographic random number generator
[Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf)
and OS-native random number generation. Note: DAuth is may only be a temporary home for these. A pull request for std.random will be made.
- **Enhancement:** Added this changelog.
- **Change:** Default digest upgraded from [SHA-1](http://en.wikipedia.org/wiki/SHA-1)
to [SHA-512](http://en.wikipedia.org/wiki/Sha2).
- **Change:** Default random number generator upgraded from
[Mt19937](http://dlang.org/phobos/std_random.html#Mt19937) to [Hash_DRBG](http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf) using SHA-512.
- **Change:** Change callbacks from function to delegate.
- **Change:** Split DAuth into separate modules (maintaining support for
```import dauth;``` via package.d).
- **Fixed:** Blindly accepted (unsupported) non-uint random number ranges
instead of rejecting them with constraints.
- **Fixed:** Calling ```isPasswordCorrect(Password, Hash!Digest)``` fails with
ugly compile error.
- **Fixed:** ```dub.json``` broken, wrong format for ```sourcePaths``` and ```importPaths```.

v0.5.1 - 2014/04/06
-------------------
- **Fixed:** [DUB](http://code.dlang.org/getting_started) package names must be all-lowercase.

v0.5.0 - 2014/04/06
-------------------
- Initial release
