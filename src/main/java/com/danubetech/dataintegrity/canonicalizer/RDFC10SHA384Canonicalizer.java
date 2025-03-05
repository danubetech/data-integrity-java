package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.keyformats.crypto.provider.SHA384Provider;

import java.security.GeneralSecurityException;

public class RDFC10SHA384Canonicalizer extends RDFC10Canonicalizer {

    private static final RDFC10SHA384Canonicalizer INSTANCE = new RDFC10SHA384Canonicalizer();

    public static RDFC10SHA384Canonicalizer getInstance() {
        return INSTANCE;
    }

    @Override
    public int hashLength() {
        return 48;
    }

    @Override
    public byte[] hash(byte[] input) throws GeneralSecurityException {
        return SHA384Provider.get().sha384(input);
    }
}
