package com.danubetech.dataintegrity.signer;

import bbs.signatures.KeyPair;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015Canonicalizer;
import com.danubetech.dataintegrity.suites.BbsBlsSignature2020DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;

public class BbsBlsSignature2020LdSigner extends LdSigner<BbsBlsSignature2020DataIntegritySuite> {

    public BbsBlsSignature2020LdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020, signer);
    }

    public BbsBlsSignature2020LdSigner(KeyPair privateKey) {
        this(new Bls12381G2_BBSPlus_PrivateKeySigner(privateKey));
    }

    public BbsBlsSignature2020LdSigner() {
        this((ByteSigner) null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        return URDNA2015Canonicalizer.getInstance();
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // sign

        String proofValue;

        byte[] bytes = signer.sign(signingInput, JWSAlgorithm.BBSPlus);
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
