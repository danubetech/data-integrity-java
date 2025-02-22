package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaKoblitzSignature2016DataIntegritySuite extends DataIntegritySuite {

	EcdsaKoblitzSignature2016DataIntegritySuite() {

		super(
				"EcdsaKoblitzSignature2016",
				URI.create("https://w3id.org/security#EcdsaKoblitzSignature2016"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#koblitz"),
				List.of(KeyTypeName.secp256k1),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
