module instauser.basic.exceptions;

/++
Thrown whenever a digest type cannot be determined.
For example, when the provided (or default) 'digestCodeOfObj' or 'digestFromCode'
delegates fail to find a match. Or when passing isSameHash a
Hash!Digest with a null 'digest' member (which prevents it from determining
the correct digest to match with).
+/
class UnknownDigestException : Exception
{
	this(string msg) { super(msg); }
}

/++
Thrown when a known-weak algortihm or setting it attempted, UNLESS
compiled with '-version=InstaUser_AllowWeakSecurity'
+/
class KnownWeakException : Exception
{
	static enum message =
		"This is known to be weak for salted password hashing. "~
		"If you understand and accept the risks, you can force InstaUser "~
		"to allow it with -version=InstaUser_AllowWeakSecurity";
	
	this(string algoName)
	{
		super(algoName ~ " - " ~ message);
	}
}
