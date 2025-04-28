package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.adapter.JWSSignerAdapter;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.JsonWebSignature2020DataIntegritySuite;
import com.danubetech.dataintegrity.util.JWSUtil;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.util.Collections;

public class JsonWebSignature2020LdSigner extends LdSigner<JsonWebSignature2020DataIntegritySuite> {

    public JsonWebSignature2020LdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020, signer);
    }

    public JsonWebSignature2020LdSigner() {
        this(null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return URDNA2015SHA256Canonicalizer.getInstance();
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // determine algorithm

        String algorithm = signer.getAlgorithm();

        // build the JWS and sign

        String jws;

        try {

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

            JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.parse(algorithm));
            Base64URL signature = jwsSigner.sign(jwsHeader, jwsSigningInput);
            jws = JWSUtil.serializeDetachedJws(jwsHeader, signature);
        } catch (JOSEException ex) {

            throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
        }

        // done

        ldProofBuilder.jws(jws);
    }

    @Override
    public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
