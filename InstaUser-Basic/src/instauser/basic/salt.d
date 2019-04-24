module instauser.basic.salt;

import instauser.basic.digest;
import instauser.basic.password;

alias Salt = ubyte[]; /// Salt type

/++
Convenience alias for any delegate that combines the salt with the
password to be hashed.

Only used by hashers (like `DigestHasher`) that don't do their own salting.
+/
alias Salter(TDigest) = void delegate(ref TDigest, Password, Salt);

/++
Default salter for hashers (like `DigestHasher`) that don't do their own salting.

Used by `makeHash` and `isSameHash` when no custom salter is provided.

Note that customized salting is unnecessary from a security perspective.
At best, it is an example of the "security through obscurity" fallacy.
Custom salting is supported only for the sake of interfacing with existing
data stores that may already be using a different method of salting.
+/
void defaultSalter(TDigest)(ref TDigest digest, Password password, Salt salt)
	if(isAnyDigest!TDigest)
{
	digest.put(cast(immutable(ubyte)[])salt);
	digest.put(password.data);
}
