package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.JCSCanonicalizer;
import com.danubetech.dataintegrity.canonicalizer.RDFC10Canonicalizer;
import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class DataIntegrityProofDataIntegritySuite extends DataIntegritySuite {

	private static final Map<String, Canonicalizer> CANONICALIZERS_BY_CRYPTOSUITE = Map.of(
			"ecdsa-rdfc-2019", RDFC10Canonicalizer.getInstance(),
			"ecdsa-jcs-2019", JCSCanonicalizer.getInstance(),
			"eddsa-rdfc-2022", RDFC10Canonicalizer.getInstance(),
			"eddsa-jcs-2022", JCSCanonicalizer.getInstance()
	);

	private static final Map<String, Map<KeyTypeName, String>> JWS_ALGORITHM_BY_CRYPTOSUITE_AND_KEY_TYPE_NAME = Map.of(
			"ecdsa-rdfc-2019", Map.of(
					KeyTypeName.secp256k1, JWSAlgorithm.ES256K,
					KeyTypeName.P_256, JWSAlgorithm.ES256,
					KeyTypeName.P_384, JWSAlgorithm.ES384,
					KeyTypeName.P_521, JWSAlgorithm.ES512
			),
			"ecdsa-jcs-2019", Map.of(
					KeyTypeName.Ed25519, JWSAlgorithm.EdDSA
			),
			"eddsa-rdfc-2022", Map.of(
					KeyTypeName.secp256k1, JWSAlgorithm.ES256K,
					KeyTypeName.P_256, JWSAlgorithm.ES256,
					KeyTypeName.P_384, JWSAlgorithm.ES384,
					KeyTypeName.P_521, JWSAlgorithm.ES512
			),
			"eddsa-jcs-2022", Map.of(
					KeyTypeName.Ed25519, JWSAlgorithm.EdDSA
			)
	);

	DataIntegrityProofDataIntegritySuite() {
		super(
				"DataIntegrityProof",
				URI.create("https://w3id.org/security#DataIntegrityProof"),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA),
						KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K),
						KeyTypeName.P_256, List.of(JWSAlgorithm.ES256),
						KeyTypeName.P_384, List.of(JWSAlgorithm.ES384),
						KeyTypeName.P_521, List.of(JWSAlgorithm.ES512)),
                List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2));
	}
}
