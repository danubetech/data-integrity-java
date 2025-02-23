package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.keyformats.jose.KeyTypeName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DataIntegritySuitesTest {

	@Test
	public void testDataIntegritySuites() throws Exception {

		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.RSA).size(), 2);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.secp256k1).size(), 5);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Ed25519).size(), 5);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.P_256).size(), 2);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.P_384).size(), 2);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Bls12381G1).size(), 1);
		assertEquals(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Bls12381G2).size(), 1);

		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.RSA).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_RSASIGNATURE2018));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.secp256k1).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSAKOBLITZSIGNATURE2016));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.secp256k1).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_ECDSASECP256L1SIGNATURE2019));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.secp256k1).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSECDSASECP256L1SIGNATURE2019));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.secp256k1).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Ed25519).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_ED25519SIGNATURE2018));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Ed25519).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_ED25519SIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Ed25519).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Ed25519).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.P_256).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.P_384).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Bls12381G1).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020));
		assertTrue(DataIntegritySuites.findDataIntegritySuitesByKeyTypeName(KeyTypeName.Bls12381G2).contains(DataIntegritySuites.DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020));
	}
}
