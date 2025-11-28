package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.JCSSHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.JcsEcdsaSecp256k1Signature2019DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.secp256k1_ES256K_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Base58;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;
import java.util.Map;

public class JcsEcdsaSecp256k1Signature2019LdSigner extends LdSigner<JcsEcdsaSecp256k1Signature2019DataIntegritySuite> {

	public JcsEcdsaSecp256k1Signature2019LdSigner(ByteSigner signer) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSECDSASECP256L1SIGNATURE2019, signer);
	}

	public JcsEcdsaSecp256k1Signature2019LdSigner(ECKey privateKey) {
		this(new secp256k1_ES256K_PrivateKeySigner(privateKey));
	}

	public JcsEcdsaSecp256k1Signature2019LdSigner() {
		this((ByteSigner) null);
	}

    @Override
	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return JCSSHA256Canonicalizer.getInstance();
	}

	public static void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String signatureValue;

		byte[] bytes = signer.sign(signingInput, JWSAlgorithm.ES256K);
		signatureValue = Base58.encode(bytes);

		// done

		ldProofBuilder.properties(Map.of("signatureValue", signatureValue));
	}

	@Override
	public void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
