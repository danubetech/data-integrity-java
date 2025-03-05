package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.signer.JsonWebSignature2020LdSigner;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.JsonWebSignature2020LdVerifier;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignJsonWebSignatureTest {

	@BeforeEach
	public void before() {

		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignJsonWebSignatureTest.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		Date expires = JsonLDUtils.DATE_FORMAT.parse("2027-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(KeyTypeName.Ed25519, JWSAlgorithm.EdDSA, TestUtil.testEd25519PrivateKey);
		JsonWebSignature2020LdSigner signer = new JsonWebSignature2020LdSigner(privateKeySigner);
		signer.setCreated(created);
		signer.setExpires(expires);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		DataIntegrityProof dataIntegrityProof = signer.sign(jsonLdObject);

		assertEquals(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020.getTerm(), dataIntegrityProof.getType());
		assertEquals(created, dataIntegrityProof.getCreated());
		assertEquals(expires, dataIntegrityProof.getExpires());
		assertEquals(domain, dataIntegrityProof.getDomain());
		assertEquals(nonce, dataIntegrityProof.getNonce());
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..Xmc-e78h7VdiibJOHCQWRLZMq7IsD-h3h8syB748Tl3VYvCHFeyF2IrAeGD8-1_GEk_UqWi-gmQhR_Wr22n3Dw", dataIntegrityProof.getJws());

		PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.Ed25519, JWSAlgorithm.EdDSA, TestUtil.testEd25519PublicKey);
		JsonWebSignature2020LdVerifier verifier = new JsonWebSignature2020LdVerifier(publicKeyVerifier);
		boolean verify = verifier.verify(jsonLdObject, dataIntegrityProof);
		assertTrue(verify);
	}
}
