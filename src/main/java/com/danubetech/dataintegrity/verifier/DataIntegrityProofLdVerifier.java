package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteVerifier;
import io.ipfs.multibase.Multibase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;

public class DataIntegrityProofLdVerifier extends LdVerifier<DataIntegrityProofDataIntegritySuite> {

	private static final Logger log = LoggerFactory.getLogger(DataIntegrityProofLdVerifier.class);

	public DataIntegrityProofLdVerifier(ByteVerifier verifier) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF, verifier);
	}

	public DataIntegrityProofLdVerifier() {
		this(null);
	}

	@Override
	public void initialize(DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		// determine algorithm and cryptosuite

		String algorithm = this.getVerifier().getAlgorithm();;
		String cryptosuite = dataIntegrityProof.getCryptosuite();

		if (cryptosuite == null) throw new GeneralSecurityException("No cryptosuite in data integrity proof: " + dataIntegrityProof);
		if (! DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF.findCryptosuitesForJwsAlgorithm(algorithm).contains(cryptosuite)) {
			throw new GeneralSecurityException("Algorithm " + algorithm + " is not supported by cryptosuite " + cryptosuite);
		}
		if (log.isDebugEnabled()) log.debug("Determined algorithm {} and cryptosuite: {}", algorithm, cryptosuite);
	}

	@Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		String cryptosuite = dataIntegrityProof.getCryptosuite();
		if (cryptosuite == null) throw new IllegalStateException("No cryptosuite: " + dataIntegrityProof);
		String algorithm = this.getVerifier().getAlgorithm();
		if (algorithm == null) throw new IllegalStateException("No algorithm: " + this.getVerifier());
		Canonicalizer canonicalizer = DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF.findCanonicalizerForCryptosuiteAndAlgorithm(cryptosuite, algorithm);
		if (canonicalizer == null) throw new IllegalArgumentException("No canonicalizer for cryptosuite " + cryptosuite + " and algorithm " + algorithm + ": " + canonicalizer);
		if (log.isDebugEnabled()) log.debug("Determined canonicalizer for algorithm {} and cryptosuite {}: {}", algorithm, cryptosuite, canonicalizer.getClass().getSimpleName());
		return canonicalizer;
	}

	@Override
	public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		return verify(signingInput, dataIntegrityProof, this.getVerifier());
	}

	public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		String proofValue = dataIntegrityProof.getProofValue();
		if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

		boolean verify;

		byte[] bytes = Multibase.decode(proofValue);
		verify = verifier.verify(signingInput, bytes, verifier.getAlgorithm());

		// done

		return verify;
	}
}
