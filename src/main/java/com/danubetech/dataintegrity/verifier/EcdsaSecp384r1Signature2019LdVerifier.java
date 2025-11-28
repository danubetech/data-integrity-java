package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.EcdsaSecp384r1Signature2019DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.P_384_ES384_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

public class EcdsaSecp384r1Signature2019LdVerifier extends LdVerifier<EcdsaSecp384r1Signature2019DataIntegritySuite> {

	public EcdsaSecp384r1Signature2019LdVerifier(ByteVerifier verifier) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP384R1SIGNATURE2019, verifier);
	}

	public EcdsaSecp384r1Signature2019LdVerifier(ECPublicKey publicKey) {
		this(new P_384_ES384_PublicKeyVerifier(publicKey));
	}

	public EcdsaSecp384r1Signature2019LdVerifier() {
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
		verify = verifier.verify(signingInput, bytes, JWSAlgorithm.ES384);

		// done

		return verify;
	}

	@Override
	public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		return verify(signingInput, dataIntegrityProof, this.getVerifier());
	}
}
