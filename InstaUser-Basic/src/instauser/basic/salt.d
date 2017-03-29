module instauser.basic.salt;

import instauser.basic.digest;
import instauser.basic.password;

alias Salt = ubyte[]; /// Salt type
alias Salter(TDigest) = void delegate(ref TDigest, Password, Salt); /// Convenience alias for salter delegates.

/// Default salter for 'makeHash' and 'isSameHash'.
void defaultSalter(TDigest)(ref TDigest digest, Password password, Salt salt)
	if(isAnyDigest!TDigest)
{
	digest.put(cast(immutable(ubyte)[])salt);
	digest.put(password.data);
}
