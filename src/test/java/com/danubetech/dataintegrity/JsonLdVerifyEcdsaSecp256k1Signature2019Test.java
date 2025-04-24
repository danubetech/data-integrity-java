package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.verifier.EcdsaSecp256k1Signature2019LdVerifier;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.good.EcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestKeys.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.bad.EcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestKeys.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
