package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.verifier.JsonWebSignature2020LdVerifier;
import com.danubetech.dataintegrity.verifier.RsaSignature2018LdVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyJsonWebSignature2020Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJsonWebSignature2020Test.class.getResourceAsStream("signed.good.JsonWebSignature2020.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.Ed25519, JWSAlgorithm.EdDSA, TestKeys.testEd25519PublicKey);
		JsonWebSignature2020LdVerifier verifier = new JsonWebSignature2020LdVerifier(publicKeyVerifier);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJsonWebSignature2020Test.class.getResourceAsStream("signed.bad.JsonWebSignature2020.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.Ed25519, JWSAlgorithm.EdDSA, TestKeys.testEd25519PublicKey);
		JsonWebSignature2020LdVerifier verifier = new JsonWebSignature2020LdVerifier(publicKeyVerifier);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
