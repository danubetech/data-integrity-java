package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.adapter.JWSSignerAdapter;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.EcdsaSecp256r1Signature2019DataIntegritySuite;
import com.danubetech.dataintegrity.util.JWSUtil;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.P_256_ES256_PrivateKeySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.util.Collections;

public class EcdsaSecp256r1Signature2019LdSigner extends LdSigner<EcdsaSecp256r1Signature2019DataIntegritySuite> {

    public EcdsaSecp256r1Signature2019LdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019, signer);
    }

    public EcdsaSecp256r1Signature2019LdSigner(ECPrivateKey privateKey) {
        this(new P_256_ES256_PrivateKeySigner(privateKey));
    }

    public EcdsaSecp256r1Signature2019LdSigner() {
        this((ByteSigner) null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return URDNA2015Canonicalizer.getInstance();
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign

        String jws;

        try {

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

            JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.ES256);
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
