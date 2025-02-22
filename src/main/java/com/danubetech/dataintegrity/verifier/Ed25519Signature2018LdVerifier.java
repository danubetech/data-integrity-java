package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.danubetech.dataintegrity.adapter.JWSVerifierAdapter;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.Ed25519Signature2018DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.util.JWSUtil;

import java.security.GeneralSecurityException;
import java.text.ParseException;

public class Ed25519Signature2018LdVerifier extends LdVerifier<Ed25519Signature2018DataIntegritySuite> {

    public Ed25519Signature2018LdVerifier(ByteVerifier verifier) {

        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ED25519SIGNATURE2018, verifier, new URDNA2015Canonicalizer());
    }

    public Ed25519Signature2018LdVerifier(byte[] publicKey) {

        this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
    }

    public Ed25519Signature2018LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // build the JWS and verify

        String jws = dataIntegrityProof.getJws();
        if (jws == null) throw new GeneralSecurityException("No 'jws' in proof.");

        boolean verify;

        try {

            JWSObject detachedJwsObject = JWSObject.parse(jws);
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

            JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.EdDSA);
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
