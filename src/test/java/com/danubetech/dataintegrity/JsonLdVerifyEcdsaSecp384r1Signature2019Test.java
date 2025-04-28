package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.verifier.EcdsaSecp384r1Signature2019LdVerifier;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyEcdsaSecp384r1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyEcdsaSecp384r1Signature2019Test.class.getResourceAsStream("signed.good.EcdsaSecp384r1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		EcdsaSecp384r1Signature2019LdVerifier verifier = new EcdsaSecp384r1Signature2019LdVerifier(TestKeys.testP384PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyEcdsaSecp384r1Signature2019Test.class.getResourceAsStream("signed.bad.EcdsaSecp384r1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		EcdsaSecp384r1Signature2019LdVerifier verifier = new EcdsaSecp384r1Signature2019LdVerifier(TestKeys.testP384PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
