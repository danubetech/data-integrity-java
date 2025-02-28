package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.RDFC10Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteSigner;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;

public class DataIntegrityProofLdSigner extends LdSigner<DataIntegrityProofDataIntegritySuite> {

    private static final Logger log = LoggerFactory.getLogger(DataIntegrityProofLdSigner.class);

    public DataIntegrityProofLdSigner(ByteSigner signer) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF, signer);
    }

    public DataIntegrityProofLdSigner() {
        this((ByteSigner) null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        String cryptosuite = dataIntegrityProof.getCryptosuite();
        if (cryptosuite == null) return RDFC10Canonicalizer.getInstance();
        Canonicalizer canonicalizer = DataIntegrityProofDataIntegritySuite.findCanonicalizerByCryptosuite(cryptosuite);
        if (canonicalizer == null) throw new IllegalArgumentException("Unknown cryptosuite: " + cryptosuite);
        return canonicalizer;
    }

    public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer, String cryptosuite) throws GeneralSecurityException {

        // determine algorithm and cryptosuite

        String algorithm;

        algorithm = signer.getAlgorithm();
        if (cryptosuite != null) {
            if (! DataIntegrityProofDataIntegritySuite.findCryptosuitesByJwsAlgorithm(algorithm).contains(cryptosuite)) {
                throw new GeneralSecurityException("Algorithm " + algorithm + " is not supported by cryptosuite " + cryptosuite);
            }
        } else {
            cryptosuite = DataIntegrityProofDataIntegritySuite.findDefaultCryptosuiteByJwsAlgorithm(algorithm);
            ldProofBuilder.cryptosuite(cryptosuite);
        }
        if (log.isDebugEnabled()) log.debug("Determined algorithm {} and cryptosuite: {}", algorithm, cryptosuite);

        // sign

        String proofValue;

        byte[] bytes = signer.sign(signingInput, algorithm);
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {
        sign(ldProofBuilder, signingInput, this.getSigner(), this.getCryptosuite());
    }
}
