package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.util.TestKeys;
import com.danubetech.dataintegrity.util.TestUtil;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.signer.RsaSignature2018LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.RsaSignature2018LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignRsaSignature2018Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		RsaSignature2018LdSigner signer = new RsaSignature2018LdSigner(TestKeys.testRSAPrivateKey);
		signer.setCreated(created);
		signer.setExpires(expires);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		DataIntegrityProof dataIntegrityProof = signer.sign(jsonLdObject);

		assertEquals(DataIntegritySuites.DATA_INTEGRITY_SUITE_RSASIGNATURE2018.getTerm(), dataIntegrityProof.getType());
		assertEquals(created, dataIntegrityProof.getCreated());
		assertEquals(expires, dataIntegrityProof.getExpires());
		assertEquals(domain, dataIntegrityProof.getDomain());
		assertEquals(nonce, dataIntegrityProof.getNonce());
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..IjvsJZgMV8-H2AgXsXI5yVgWb4Y4jHE7c2TdDJ-yp1mDn9A9gvM-nTlr2HjgKvJuMmJqshMOM-inKNj63dbRMoviU2iDTyjUc0Jg85XxcOXjQYZ1eCvxkOo1yC1Zka9sMZG7-SlERrNPktHlAZ_nBvWqb_6d-wd1roHHI4dWLgBr2qhxyZNSilsCh0eTGNqROvnCNAxKNFbSF0-gnuDYZZiyMe3aqcrCf0JhDIAEsUB3AUeko8TnRGZ5NBY9FLj-EGgr3YugIU4KKKeiEgxYITL3mKErOGfJxyrVeEX8o9hCWkUkfEtYggtpYdOkA9_CmVKIq_oiynemah-3D8ZMXw", dataIntegrityProof.getJws());

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestKeys.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
