package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.RDFC10Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteVerifier;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;

public class DataIntegrityProofLdVerifier extends LdVerifier<DataIntegrityProofDataIntegritySuite> {

    public DataIntegrityProofLdVerifier(ByteVerifier verifier) {
        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF, verifier);
    }

    public DataIntegrityProofLdVerifier() {
        this(null);
    }

    public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
        String cryptosuite = dataIntegrityProof.getCryptosuite();
        if (cryptosuite == null) return RDFC10Canonicalizer.getInstance();
        Canonicalizer canonicalizer = DataIntegrityProofDataIntegritySuite.findCanonicalizerByCryptosuite(cryptosuite);
        if (canonicalizer == null) throw new IllegalArgumentException("Unknown cryptosuite: " + cryptosuite);
        return canonicalizer;
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // determine algorithm and cryptosuite

        String cryptosuite = dataIntegrityProof.getCryptosuite();
        if (cryptosuite == null) throw new GeneralSecurityException("No cryptosuite in data integrity proof: " + dataIntegrityProof);

        String algorithm;

        algorithm = verifier.getAlgorithm();
        if (! DataIntegrityProofDataIntegritySuite.findCryptosuitesByJwsAlgorithm(algorithm).contains(cryptosuite)) {
            throw new GeneralSecurityException("Algorithm " + algorithm + " is not supported by cryptosuite " + cryptosuite);
        }

        // verify

        String proofValue = dataIntegrityProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

        boolean verify;

        byte[] bytes = Multibase.decode(proofValue);
        verify = verifier.verify(signingInput, bytes, algorithm);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {
        return verify(signingInput, dataIntegrityProof, this.getVerifier());
    }
}
