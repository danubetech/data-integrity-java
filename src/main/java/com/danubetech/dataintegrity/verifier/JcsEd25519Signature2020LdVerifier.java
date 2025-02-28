package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.JCSCanonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.JcsEd25519Signature2020DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Base58;

import java.security.GeneralSecurityException;

public class JcsEd25519Signature2020LdVerifier extends LdVerifier<JcsEd25519Signature2020DataIntegritySuite> {

    public JcsEd25519Signature2020LdVerifier(ByteVerifier verifier) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020, verifier);
    }

    public JcsEd25519Signature2020LdVerifier(byte[] publicKey) {
        this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
    }

    public JcsEd25519Signature2020LdVerifier() {
        this((ByteVerifier) null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return JCSCanonicalizer.getInstance();
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String signatureValue = (String) dataIntegrityProof.getJsonObject().get("signatureValue");
        if (signatureValue == null) throw new GeneralSecurityException("No 'signatureValue' in proof.");

        boolean verify;

        byte[] bytes = Base58.decode(signatureValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

        return verify(signingInput, dataIntegrityProof, this.getVerifier());
    }
}
