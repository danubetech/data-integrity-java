package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA384Provider;

import java.security.GeneralSecurityException;

public class RDFC10SHA512Canonicalizer extends RDFC10Canonicalizer {

    private static final RDFC10SHA512Canonicalizer INSTANCE = new RDFC10SHA512Canonicalizer();

    public static RDFC10SHA512Canonicalizer getInstance() {
        return INSTANCE;
    }

    @Override
    public int hashLength() {
        return 64;
    }

    @Override
    public byte[] hash(byte[] input) throws GeneralSecurityException {
        return SHA384Provider.get().sha384(input);
    }
}
