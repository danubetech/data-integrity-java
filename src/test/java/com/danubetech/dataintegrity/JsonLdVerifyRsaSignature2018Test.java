package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.util.TestUtil;
import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.verifier.RsaSignature2018LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.good.RsaSignature2018.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestKeys.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.bad.RsaSignature2018.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestKeys.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
