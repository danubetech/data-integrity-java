package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.EcdsaSecp256r1Signature2019DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.P_256_ES256_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.util.Objects;

public class EcdsaSecp256r1Signature2019LdSigner extends LdSigner<EcdsaSecp256r1Signature2019DataIntegritySuite> {

	public EcdsaSecp256r1Signature2019LdSigner(ByteSigner signer) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019, signer);
	}

	public EcdsaSecp256r1Signature2019LdSigner(ECPrivateKey privateKey) {
		this(new P_256_ES256_PrivateKeySigner(privateKey));
	}

	public EcdsaSecp256r1Signature2019LdSigner() {
		this((ByteSigner) null);
	}

    @Override
    public void initialize(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> proofOptionsBuilder, JsonLDObject jsonLDObject) throws GeneralSecurityException {
        proofOptionsBuilder.forceContextsArray(true).contexts(jsonLDObject.getContexts().stream().filter(Objects::nonNull).toList());
    }

    @Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return URDNA2015SHA256Canonicalizer.getInstance();
	}

	public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String proofValue;

		byte[] bytes = signer.sign(signingInput, JWSAlgorithm.ES256);
		proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

		// done

		ldProofBuilder.proofValue(proofValue);
	}

	@Override
	public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
