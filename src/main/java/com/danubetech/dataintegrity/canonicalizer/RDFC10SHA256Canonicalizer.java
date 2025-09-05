package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;

import java.security.GeneralSecurityException;

public class RDFC10SHA256Canonicalizer extends RDFC10Canonicalizer {

	private static final RDFC10SHA256Canonicalizer INSTANCE = new RDFC10SHA256Canonicalizer();

	public static RDFC10SHA256Canonicalizer getInstance() {
		return INSTANCE;
	}

	@Override
	public String hashAlgorithm() {
		return "SHA-256";
	}

	@Override
	public int hashLength() {
		return 32;
	}

	@Override
	public byte[] hash(byte[] input) throws GeneralSecurityException {
		return SHA256Provider.get().sha256(input);
	}
}
