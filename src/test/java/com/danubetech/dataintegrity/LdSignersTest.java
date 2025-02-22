package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.signer.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdSignersTest {

	@Test
	public void testLdSigners() throws Exception {

		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("RsaSignature2018").getClass(), RsaSignature2018LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("Ed25519Signature2018").getClass(), Ed25519Signature2018LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("Ed25519Signature2020").getClass(), Ed25519Signature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("JcsEd25519Signature2020").getClass(), JcsEd25519Signature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("EcdsaSecp256k1Signature2019").getClass(), EcdsaSecp256k1Signature2019LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("JcsEcdsaSecp256k1Signature2019").getClass(), JcsEcdsaSecp256k1Signature2019LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("BbsBlsSignature2020").getClass(), BbsBlsSignature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm("JsonWebSignature2020").getClass(), JsonWebSignature2020LdSigner.class);
	}
}
