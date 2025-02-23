package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.JCSCanonicalizer;
import com.danubetech.dataintegrity.canonicalizer.RDFC10Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.Ed25519Signature2020DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;

public class DataIntegrityProofLdSigner extends LdSigner<DataIntegrityProofDataIntegritySuite> {

    public DataIntegrityProofLdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF, signer);
    }

    public DataIntegrityProofLdSigner(byte[] privateKey) {
        this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
    }

    public DataIntegrityProofLdSigner() {
        this((ByteSigner) null);
    }

    public Canonicalizer getCanonicalizer() {
        return RDFC10Canonicalizer.getInstance();
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // sign

        String proofValue;

        byte[] bytes = signer.sign(signingInput, signer.getAlgorithm());
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {
        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
