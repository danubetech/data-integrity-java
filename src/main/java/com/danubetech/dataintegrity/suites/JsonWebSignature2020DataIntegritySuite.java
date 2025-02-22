package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class JsonWebSignature2020DataIntegritySuite extends DataIntegritySuite {

	JsonWebSignature2020DataIntegritySuite() {

		super(
				"JsonWebSignature2020",
				URI.create("https://w3id.org/security#JsonWebSignature2020"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("https://registry.ietf.org/ietf-digest-algorithms#SHA256"),
				null,
				List.of(KeyTypeName.RSA,
						KeyTypeName.Ed25519,
						KeyTypeName.secp256k1,
						KeyTypeName.P_256,
						KeyTypeName.P_384),
				Map.of(KeyTypeName.RSA, List.of(JWSAlgorithm.PS256, JWSAlgorithm.RS256),
						KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA),
						KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K),
						KeyTypeName.P_256, List.of(JWSAlgorithm.ES256),
						KeyTypeName.P_384, List.of(JWSAlgorithm.ES384)),
				List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_JWS_2020_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
