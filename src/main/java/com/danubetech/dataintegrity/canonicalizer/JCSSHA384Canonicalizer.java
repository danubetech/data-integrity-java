package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA384Provider;

import java.security.GeneralSecurityException;

public class JCSSHA384Canonicalizer extends JCSCanonicalizer {

    private static final JCSSHA384Canonicalizer INSTANCE = new JCSSHA384Canonicalizer();

    public static JCSSHA384Canonicalizer getInstance() {
        return INSTANCE;
    }

    public int hashLength() {
        return 48;
    }

    public byte[] hash(byte[] input) throws GeneralSecurityException {
        return SHA384Provider.get().sha384(input);
    }
}
