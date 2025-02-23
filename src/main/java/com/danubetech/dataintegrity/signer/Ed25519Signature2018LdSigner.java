package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.danubetech.dataintegrity.adapter.JWSSignerAdapter;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.Ed25519Signature2018DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.util.JWSUtil;

import java.security.GeneralSecurityException;
import java.util.Collections;

public class Ed25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018DataIntegritySuite> {

    public Ed25519Signature2018LdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ED25519SIGNATURE2018, signer);
    }

    public Ed25519Signature2018LdSigner(byte[] privateKey) {
        this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
    }

    public Ed25519Signature2018LdSigner() {
        this((ByteSigner) null);
    }

    public Canonicalizer getCanonicalizer() {
        return URDNA2015Canonicalizer.getInstance();
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign

        String jws;

        try {

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

            JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.EdDSA);
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
