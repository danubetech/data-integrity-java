package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.JCSSHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.JcsEd25519Signature2020DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Base58;

import java.security.GeneralSecurityException;
import java.util.Map;

public class JcsEd25519Signature2020LdSigner extends LdSigner<JcsEd25519Signature2020DataIntegritySuite> {

	public JcsEd25519Signature2020LdSigner(ByteSigner signer) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020, signer);
	}

	public JcsEd25519Signature2020LdSigner(byte[] privateKey) {
		this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
	}

	public JcsEd25519Signature2020LdSigner() {
		this((ByteSigner) null);
	}

    @Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return JCSSHA256Canonicalizer.getInstance();
	}

	public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String signatureValue;

		byte[] bytes = signer.sign(signingInput, JWSAlgorithm.EdDSA);
		signatureValue = Base58.encode(bytes);

		// done

		ldProofBuilder.properties(Map.of("signatureValue", signatureValue));
	}

	@Override
	public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
