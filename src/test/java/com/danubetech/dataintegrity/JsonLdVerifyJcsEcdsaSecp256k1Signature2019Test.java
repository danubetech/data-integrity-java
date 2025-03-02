package com.danubetech.dataintegrity;

import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.verifier.JcsEcdsaSecp256k1Signature2019LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.good.JcsEcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		JcsEcdsaSecp256k1Signature2019LdVerifier verifier = new JcsEcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.bad.JcsEcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		JcsEcdsaSecp256k1Signature2019LdVerifier verifier = new JcsEcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
