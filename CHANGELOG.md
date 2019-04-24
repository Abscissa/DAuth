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
- **Change**: Split up "core" module into smaller modules.
- **Enhancement:** Tested via [travis.ci](https://travis-ci.org/).
