package com.danubetech.dataintegrity;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.signer.JcsEd25519Signature2020LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.JcsEd25519Signature2020LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignJcsEd25519Signature2020Test {

	@BeforeEach
	public void before() {

		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignJcsEd25519Signature2020Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		JcsEd25519Signature2020LdSigner signer = new JcsEd25519Signature2020LdSigner(TestUtil.testEd25519PrivateKey);
		signer.setCreated(created);
		signer.setExpires(expires);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		DataIntegrityProof dataIntegrityProof = signer.sign(jsonLdObject);

		assertEquals(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020.getTerm(), dataIntegrityProof.getType());
		assertEquals(created, dataIntegrityProof.getCreated());
		assertEquals(expires, dataIntegrityProof.getExpires());
		assertEquals(domain, dataIntegrityProof.getDomain());
		assertEquals(nonce, dataIntegrityProof.getNonce());
		assertEquals("2J5zk5WfSDEFCC9rBzC4Vq7rGLnjg7wDmQcE6Ki1VLbEdZKa6qiqeKdAPRcGshxgBkBnN1QzEzSow48LfdHVZPrS", dataIntegrityProof.getJsonObject().get("signatureValue"));

		JcsEd25519Signature2020LdVerifier verifier = new JcsEd25519Signature2020LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
