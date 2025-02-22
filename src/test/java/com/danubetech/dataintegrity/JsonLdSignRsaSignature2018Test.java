package com.danubetech.dataintegrity;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.dataintegrity.signer.RsaSignature2018LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.RsaSignature2018LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignRsaSignature2018Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		RsaSignature2018LdSigner signer = new RsaSignature2018LdSigner(TestUtil.testRSAPrivateKey);
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
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..DC_s_jGp_oqrlGUM7IGIXktfEqZNGgwN_ECBy5Ln5LLxyZi0PMEDx3QuQsZJL6Qr4FVsGEOX878ekGKz5a2YiycXx-NLZwAUz06Ev3oaOQW3b3Qm6UelIqr5VeRoEgSxYDVv1O8favrxf1crBbYz_j2UTmbvrBSesI6EMj_u3TOfMb0y5kG6moRR8rTEg3Qi1Lf-9BafoFBmMo3IvWIt7L4yOkoYst2UdOQw7jOBLbtgJZ-6HcshFIfR3hrtT9NwB8ezWcUri6DXzy3Ty_kT5sgCCTqqQWinR5TJ3NWBWqtsZor-1fUks65CbJWv-5VTc_rKRndT58yCv6Cro40Fhw", dataIntegrityProof.getJws());

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
