package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.adapter.JWSVerifierAdapter;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.suites.RsaSignature2018DataIntegritySuite;
import com.danubetech.dataintegrity.util.JWSUtil;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.RSA_RS256_PublicKeyVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class RsaSignature2018LdVerifier extends LdVerifier<RsaSignature2018DataIntegritySuite> {

	public RsaSignature2018LdVerifier(ByteVerifier verifier) {
		super(DataIntegritySuites.DATA_INTEGRITY_SUITE_RSASIGNATURE2018, verifier);
	}

	public RsaSignature2018LdVerifier(RSAPublicKey publicKey) {
		this(new RSA_RS256_PublicKeyVerifier(publicKey));
	}

	public RsaSignature2018LdVerifier() {
		this((ByteVerifier) null);
	}

	public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
		return URDNA2015SHA256Canonicalizer.getInstance();
	}

	public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

		// build the JWS and verify

		String jws = dataIntegrityProof.getJws();
		boolean verify;

		try {

			JWSObject detachedJwsObject = JWSObject.parse(jws);
			byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.RS256);
			verify = jwsVerifier.verify(detachedJwsObject.getHeader(), jwsSigningInput, detachedJwsObject.getSignature());
		} catch (JOSEException | ParseException ex) {

			throw new GeneralSecurityException("JOSE verification problem: " + ex.getMessage(), ex);
		}

		// done

		return verify;
	}

	@Override
	public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

		return verify(signingInput, dataIntegrityProof, this.getVerifier());
	}
}
