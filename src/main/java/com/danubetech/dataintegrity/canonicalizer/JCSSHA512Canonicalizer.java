package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA512Provider;

import java.security.GeneralSecurityException;

public class JCSSHA512Canonicalizer extends JCSCanonicalizer {

	private static final JCSSHA512Canonicalizer INSTANCE = new JCSSHA512Canonicalizer();

	public static JCSSHA512Canonicalizer getInstance() {
		return INSTANCE;
	}

	public int hashLength() {
		return 64;
	}

	public byte[] hash(byte[] input) throws GeneralSecurityException {
		return SHA512Provider.get().sha512(input);
	}
}
