package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
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

	@Override
	public void initialize(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder) throws GeneralSecurityException {

		// determine algorithm and cryptosuite

		String algorithm = this.getSigner().getAlgorithm();
		String cryptosuite = this.getCryptosuite();

		if (cryptosuite != null) {
			if (! DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF.findCryptosuitesForJwsAlgorithm(algorithm).contains(cryptosuite)) {
				throw new GeneralSecurityException("Algorithm " + algorithm + " is not supported by cryptosuite " + cryptosuite);
			}
		} else {
			cryptosuite = DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF.findDefaultCryptosuiteForJwsAlgorithm(algorithm);
			ldProofBuilder.cryptosuite(cryptosuite);
		}
		if (log.isDebugEnabled()) log.debug("Determined algorithm {} and cryptosuite: {}", algorithm, cryptosuite);
	}

	@Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		String cryptosuite = dataIntegrityProof.getCryptosuite();
		if (cryptosuite == null) throw new IllegalStateException("No cryptosuite: " + dataIntegrityProof);
		String algorithm = this.getSigner().getAlgorithm();
		if (algorithm == null) throw new IllegalStateException("No algorithm: " + this.getSigner());
		Canonicalizer canonicalizer = DataIntegritySuites.DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF.findCanonicalizerForCryptosuiteAndAlgorithm(cryptosuite, algorithm);
		if (canonicalizer == null) throw new IllegalArgumentException("No canonicalizer for cryptosuite " + cryptosuite + " and algorithm " + algorithm + ": " + canonicalizer);
		if (log.isDebugEnabled()) log.debug("Determined canonicalizer for algorithm {} and cryptosuite {}: {}", algorithm, cryptosuite, canonicalizer.getClass().getSimpleName());
		return canonicalizer;
	}

	@Override
	public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}

	public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String proofValue;

		byte[] bytes = signer.sign(signingInput, signer.getAlgorithm());
		proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

		// done

		ldProofBuilder.proofValue(proofValue);
	}
}
