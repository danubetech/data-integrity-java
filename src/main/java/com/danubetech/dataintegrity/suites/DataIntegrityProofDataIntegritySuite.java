package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class DataIntegrityProofDataIntegritySuite extends DataIntegritySuite {

	DataIntegrityProofDataIntegritySuite() {

		super(
				"DataIntegrityProof",
				URI.create("https://w3id.org/security#JsonWebSignature2020"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("https://registry.ietf.org/ietf-digest-algorithms#SHA256"),
				null,
				List.of(KeyTypeName.Ed25519,
						KeyTypeName.secp256k1,
						KeyTypeName.P_256,
						KeyTypeName.P_384),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA),
						KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K),
						KeyTypeName.P_256, List.of(JWSAlgorithm.ES256),
						KeyTypeName.P_384, List.of(JWSAlgorithm.ES384)),
                List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2));
	}
}
