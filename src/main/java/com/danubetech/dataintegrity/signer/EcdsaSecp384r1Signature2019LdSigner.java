package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA384Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.EcdsaSecp384r1Signature2019DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.P_384_ES384_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;

public class EcdsaSecp384r1Signature2019LdSigner extends LdSigner<EcdsaSecp384r1Signature2019DataIntegritySuite> {

	public EcdsaSecp384r1Signature2019LdSigner(ByteSigner signer) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP384R1SIGNATURE2019, signer);
	}

	public EcdsaSecp384r1Signature2019LdSigner(ECPrivateKey privateKey) {
		this(new P_384_ES384_PrivateKeySigner(privateKey));
	}

	public EcdsaSecp384r1Signature2019LdSigner() {
		this((ByteSigner) null);
	}

	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return URDNA2015SHA384Canonicalizer.getInstance();
	}

	public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String proofValue;

		byte[] bytes = signer.sign(signingInput, JWSAlgorithm.ES384);
		proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

		// done

		ldProofBuilder.proofValue(proofValue);
	}

	@Override
	public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
