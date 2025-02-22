package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.verifier.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdVerifiersTest {

	@Test
	public void testLdVerifiers() throws Exception {

		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("RsaSignature2018").getClass(), RsaSignature2018LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("Ed25519Signature2018").getClass(), Ed25519Signature2018LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("Ed25519Signature2020").getClass(), Ed25519Signature2020LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("JcsEd25519Signature2020").getClass(), JcsEd25519Signature2020LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("EcdsaSecp256k1Signature2019").getClass(), EcdsaSecp256k1Signature2019LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("JcsEcdsaSecp256k1Signature2019").getClass(), JcsEcdsaSecp256k1Signature2019LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("BbsBlsSignature2020").getClass(), BbsBlsSignature2020LdVerifier.class);
		assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm("JsonWebSignature2020").getClass(), JsonWebSignature2020LdVerifier.class);
	}
}
