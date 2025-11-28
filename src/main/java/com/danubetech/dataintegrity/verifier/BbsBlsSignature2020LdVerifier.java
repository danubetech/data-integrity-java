package com.danubetech.dataintegrity.verifier;

import bbs.signatures.KeyPair;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.BbsBlsSignature2020DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Bls12381G2_BBSPlus_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.util.Objects;

public class BbsBlsSignature2020LdVerifier extends LdVerifier<BbsBlsSignature2020DataIntegritySuite> {

	public BbsBlsSignature2020LdVerifier(ByteVerifier verifier) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020, verifier);
	}

	public BbsBlsSignature2020LdVerifier(KeyPair publicKey) {
		this(new Bls12381G2_BBSPlus_PublicKeyVerifier(publicKey));
	}

	public BbsBlsSignature2020LdVerifier() {
		this((ByteVerifier) null);
	}

    @Override
    public void initialize(DataIntegrityProof dataIntegrityProof, DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> proofOptionsBuilder, JsonLDObject jsonLDObject) throws GeneralSecurityException {
        proofOptionsBuilder.forceContextsArray(true).contexts(jsonLDObject.getContexts().stream().filter(Objects::nonNull).toList());
    }

    @Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return URDNA2015SHA256Canonicalizer.getInstance();
	}

	public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		String proofValue = dataIntegrityProof.getProofValue();
		if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

		boolean verify;

		byte[] bytes = Multibase.decode(proofValue);
		verify = verifier.verify(signingInput, bytes, JWSAlgorithm.BBSPlus);

		// done

		return verify;
	}

	@Override
	public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		return verify(signingInput, dataIntegrityProof, this.getVerifier());
	}
}
