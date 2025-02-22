package com.danubetech.dataintegrity;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.dataintegrity.signer.EcdsaSecp256k1Signature2019LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.EcdsaSecp256k1Signature2019LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSignEcdsaSecp256k1Signature2019() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		EcdsaSecp256k1Signature2019LdSigner signer = new EcdsaSecp256k1Signature2019LdSigner(TestUtil.testSecp256k1PrivateKey);
		signer.setCreated(created);
		signer.setExpires(expires);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		DataIntegrityProof dataIntegrityProof = signer.sign(jsonLdObject);

		assertEquals(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256L1SIGNATURE2019.getTerm(), dataIntegrityProof.getType());
		assertEquals(created, dataIntegrityProof.getCreated());
		assertEquals(expires, dataIntegrityProof.getExpires());
		assertEquals(domain, dataIntegrityProof.getDomain());
		assertEquals(nonce, dataIntegrityProof.getNonce());
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFUzI1NksifQ..eAR-59nSpsSN3IlNLjeOFufsvGkymv-pF36kXzzpA0YbaQBZywhU7gAC3fH7MoJZfqA69YzpTFpVSIttMQ8f7w", dataIntegrityProof.getJws());

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
