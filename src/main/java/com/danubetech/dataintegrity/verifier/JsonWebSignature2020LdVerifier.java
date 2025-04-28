package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.adapter.JWSVerifierAdapter;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.JsonWebSignature2020DataIntegritySuite;
import com.danubetech.dataintegrity.util.JWSUtil;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;

import java.security.GeneralSecurityException;
import java.text.ParseException;

public class JsonWebSignature2020LdVerifier extends LdVerifier<JsonWebSignature2020DataIntegritySuite> {

    public JsonWebSignature2020LdVerifier(ByteVerifier verifier) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020, verifier);
    }

    public JsonWebSignature2020LdVerifier() {
        this(null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return URDNA2015SHA256Canonicalizer.getInstance();
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // build the JWS and verify

        String jws = dataIntegrityProof.getJws();
        if (jws == null) throw new GeneralSecurityException("No 'jws' in proof.");

        boolean verify;

        try {

            JWSObject detachedJwsObject = JWSObject.parse(jws);
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

            JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.parse(verifier.getAlgorithm()));
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
