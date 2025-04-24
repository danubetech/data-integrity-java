package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.adapter.JWSVerifierAdapter;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.EcdsaSecp256r1Signature2019DataIntegritySuite;
import com.danubetech.dataintegrity.util.JWSUtil;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.P_256_ES256_PublicKeyVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

public class EcdsaSecp256r1Signature2019LdVerifier extends LdVerifier<EcdsaSecp256r1Signature2019DataIntegritySuite> {

    public EcdsaSecp256r1Signature2019LdVerifier(ByteVerifier verifier) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019, verifier);
    }

    public EcdsaSecp256r1Signature2019LdVerifier(ECPublicKey publicKey) {
        this(new P_256_ES256_PublicKeyVerifier(publicKey));
    }

    public EcdsaSecp256r1Signature2019LdVerifier() {
        this((ByteVerifier) null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return URDNA2015Canonicalizer.getInstance();
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // build the JWS and verify

        String jws = dataIntegrityProof.getJws();
        if (jws == null) throw new GeneralSecurityException("No 'jws' in proof.");

        boolean verify;

        try {

            JWSObject detachedJwsObject = JWSObject.parse(jws);
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

            JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.ES256);
            verify = jwsVerifier.verify(detachedJwsObject.getHeader(), jwsSigningInput, detachedJwsObject.getSignature());
        } catch (JOSEException | ParseException ex) {

            throw new GeneralSecurityException("JOSE verification problem: " + ex.getMessage(), ex);
        }

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

        return verify(signingInput, dataIntegrityProof, this.getVerifier());
    }
}
