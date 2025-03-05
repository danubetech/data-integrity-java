package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;

import java.security.GeneralSecurityException;

public class JCSSHA256Canonicalizer extends JCSCanonicalizer {

    private static final JCSSHA256Canonicalizer INSTANCE = new JCSSHA256Canonicalizer();

    public static JCSSHA256Canonicalizer getInstance() {
        return INSTANCE;
    }

    public int hashLength() {
        return 32;
    }

    public byte[] hash(byte[] input) throws GeneralSecurityException {
        return SHA256Provider.get().sha256(input);
    }
}
