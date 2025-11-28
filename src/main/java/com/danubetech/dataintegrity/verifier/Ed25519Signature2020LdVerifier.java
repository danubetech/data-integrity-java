package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.Ed25519Signature2020DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.util.Objects;

public class Ed25519Signature2020LdVerifier extends LdVerifier<Ed25519Signature2020DataIntegritySuite> {

	public Ed25519Signature2020LdVerifier(ByteVerifier verifier) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ED25519SIGNATURE2020, verifier);
	}

	public Ed25519Signature2020LdVerifier(byte[] publicKey) {
		this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
	}

	public Ed25519Signature2020LdVerifier() {
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
		verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

		// done

		return verify;
	}

	@Override
	public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		return verify(signingInput, dataIntegrityProof, this.getVerifier());
	}
}
