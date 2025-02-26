package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.RDFC10Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
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

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        String cryptosuite = dataIntegrityProof.getCryptosuite();
        if (cryptosuite == null) return RDFC10Canonicalizer.getInstance();
        return DataIntegrityProofDataIntegritySuite.findCanonicalizerByCryptosuite(cryptosuite);
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // determine algorithm and cryptosuite

        String algorithm;
        String cryptosuite;

        algorithm = signer.getAlgorithm();
        cryptosuite = ldProofBuilder.build().getCryptosuite();
        if (cryptosuite != null) {
            if (! DataIntegrityProofDataIntegritySuite.findCryptosuitesByJwsAlgorithm(algorithm).contains(cryptosuite)) {
                throw new GeneralSecurityException("Algorithm " + algorithm + " is not supported by cryptosuite " + cryptosuite);
            }
        } else {
            cryptosuite = DataIntegrityProofDataIntegritySuite.findDefaultCryptosuiteByJwsAlgorithm(algorithm);
            ldProofBuilder.cryptosuite(cryptosuite);
        }

        // sign

        String proofValue;

        byte[] bytes = signer.sign(signingInput, algorithm);
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {
        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
