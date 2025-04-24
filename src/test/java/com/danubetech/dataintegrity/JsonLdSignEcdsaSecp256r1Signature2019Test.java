package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.signer.EcdsaSecp256r1Signature2019LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.verifier.EcdsaSecp256r1Signature2019LdVerifier;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignEcdsaSecp256r1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSignEcdsaSecp256r1Signature2019() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignEcdsaSecp256r1Signature2019Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		EcdsaSecp256r1Signature2019LdSigner signer = new EcdsaSecp256r1Signature2019LdSigner(TestKeys.testP256PrivateKey);
		signer.setCreated(created);
		signer.setExpires(expires);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		DataIntegrityProof dataIntegrityProof = signer.sign(jsonLdObject);

		assertEquals(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019.getTerm(), dataIntegrityProof.getType());
		assertEquals(created, dataIntegrityProof.getCreated());
		assertEquals(expires, dataIntegrityProof.getExpires());
		assertEquals(domain, dataIntegrityProof.getDomain());
		assertEquals(nonce, dataIntegrityProof.getNonce());

		System.out.println(jsonLdObject.toJson());

		EcdsaSecp256r1Signature2019LdVerifier verifier = new EcdsaSecp256r1Signature2019LdVerifier(TestKeys.testP256PublicKey);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
