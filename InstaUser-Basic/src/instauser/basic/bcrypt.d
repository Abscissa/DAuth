module instauser.basic.bcrypt;

import botan.passhash.bcrypt;
import instauser.basic.hasher;
import instauser.basic.password;
import instauser.basic.salt;

struct BcryptHasher
{
	static enum hashLength = 24;
	static enum defaultWorkFactor = 10;

	ushort workFactor = defaultWorkFactor;

	/++
	Perform Bcrypt hashing.

	Adapted from Botan's `botan.passhash.bcrypt.makeBcrypt`.

	Botan_license:
	------------------------------------
	`
	Copyright (C) 1999-2015 Jack Lloyd
				2001 Peter J Jones
				2004-2007 Justin Karneges
				2004 Vaclav Ovsik
				2005 Matthew Gregan
				2005-2006 Matt Johnston
				2006 Luca Piccarreta
				2007 Yves Jerschow
				2007-2008 FlexSecure GmbH
				2007-2008 Technische Universitat Darmstadt
				2007-2008 Falko Strenzke
				2007-2008 Martin Doering
				2007 Manuel Hartl
				2007 Christoph Ludwig
				2007 Patrick Sona
				2008 Google Inc.
				2010 Olivier de Gaalon
				2012 Vojtech Kral
				2012-2014 Markus Wanner
				2013 Joel Low
				2014 Andrew Moon
				2014-2015 Etienne Cimon
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice,
		this list of conditions, and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions, and the following disclaimer in the
		documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
	`
	+/
	ubyte[hashLength] hash(Password pass, Salt salt)
	{
		enum ubyte[24] initialState = "OrpheanBeholderScryDoubt";

		auto blowfish = new Blowfish();
		ubyte[] ctext = initialState.dup;

		// Include the trailing NULL ubyte
		blowfish.eksKeySchedule(cast(const(ubyte)*) pass.toStringz, pass.length + 1, salt.ptr[0..16], workFactor);

		foreach(size_t i; 0 .. 64)
			blowfish.encryptN(ctext.ptr, ctext.ptr, 3);

		return ctext[0..hashLength];
		//auto result = bcryptBase64Encode(ctext.ptr, ctext.length - 1);
		//assert(result.length == hashLength);
		//return result[0..hashLength];
	}
}
