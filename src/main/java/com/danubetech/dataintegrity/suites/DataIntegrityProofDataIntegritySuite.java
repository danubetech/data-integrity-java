package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.canonicalizer.*;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DataIntegrityProofDataIntegritySuite extends DataIntegritySuite {

	private static final Map<String, Map<String, Canonicalizer>> CANONICALIZERS_BY_CRYPTOSUITE_AND_ALGORITHM = Map.of(
			"eddsa-rdfc-2022", Map.of(
					JWSAlgorithm.EdDSA, RDFC10SHA256Canonicalizer.getInstance()
			),
			"eddsa-jcs-2022", Map.of(
					JWSAlgorithm.EdDSA, JCSSHA256Canonicalizer.getInstance()
			),
			"ecdsa-rdfc-2019", Map.of(
					JWSAlgorithm.ES256K, RDFC10SHA256Canonicalizer.getInstance(),
					JWSAlgorithm.ES256, RDFC10SHA256Canonicalizer.getInstance(),
					JWSAlgorithm.ES384, RDFC10SHA384Canonicalizer.getInstance(),
					JWSAlgorithm.ES512, RDFC10SHA512Canonicalizer.getInstance()
			),
			"ecdsa-jcs-2019", Map.of(
					JWSAlgorithm.ES256K, JCSSHA256Canonicalizer.getInstance(),
					JWSAlgorithm.ES256, JCSSHA256Canonicalizer.getInstance(),
					JWSAlgorithm.ES384, JCSSHA384Canonicalizer.getInstance(),
					JWSAlgorithm.ES512, JCSSHA512Canonicalizer.getInstance()
			),
			"bip340-rdfc-2025", Map.of(
					JWSAlgorithm.ES256KS, RDFC10SHA256Canonicalizer.getInstance()
			),
			"bip340-jcs-2025", Map.of(
					JWSAlgorithm.ES256KS, JCSSHA256Canonicalizer.getInstance()
			)
	);

	private static final Map<String, List<String>> CRYPTOSUITES_BY_JWS_ALGORITHM = Map.of(
			JWSAlgorithm.EdDSA, List.of("eddsa-rdfc-2022", "eddsa-jcs-2022"),
			JWSAlgorithm.ES256K, List.of("ecdsa-rdfc-2019", "ecdsa-jcs-2019"),
			JWSAlgorithm.ES256KS, List.of("bip340-rdfc-2025", "bip340-jcs-2025"),
			JWSAlgorithm.ES256, List.of("ecdsa-rdfc-2019", "ecdsa-jcs-2019"),
			JWSAlgorithm.ES384, List.of("ecdsa-rdfc-2019", "ecdsa-jcs-2019"),
			JWSAlgorithm.ES512, List.of("ecdsa-rdfc-2019", "ecdsa-jcs-2019")
	);

	DataIntegrityProofDataIntegritySuite() {
		super(
				"DataIntegrityProof",
				URI.create("https://w3id.org/security#DataIntegrityProof"),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA),
						KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K, JWSAlgorithm.ES256KS),
						KeyTypeName.P_256, List.of(JWSAlgorithm.ES256),
						KeyTypeName.P_384, List.of(JWSAlgorithm.ES384),
						KeyTypeName.P_521, List.of(JWSAlgorithm.ES512)),
                List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2, DataIntegrityContexts.JSONLD_CONTEXT_W3C_CREDENTIALS_V2));
	}

	@Override
	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName, String cryptosuite) {
		List<String> jwsAlgorithms = super.findJwsAlgorithmsForKeyTypeName(keyTypeName, cryptosuite);
		if (cryptosuite != null) jwsAlgorithms = jwsAlgorithms.stream().filter(jwsAlgorithm -> this.findCryptosuitesForJwsAlgorithm(jwsAlgorithm).contains(cryptosuite)).collect(Collectors.toList());
		return jwsAlgorithms;
	}

	public Canonicalizer findCanonicalizerForCryptosuiteAndAlgorithm(String cryptosuite, String algorithm) {
		Map<String, Canonicalizer> canonicalizersByCryptosuite = CANONICALIZERS_BY_CRYPTOSUITE_AND_ALGORITHM.get(cryptosuite);
		if (canonicalizersByCryptosuite == null) return null;
		return canonicalizersByCryptosuite.get(algorithm);
	}

	public List<String> findCryptosuitesForJwsAlgorithm(String jwsAlgorithm) {
		return CRYPTOSUITES_BY_JWS_ALGORITHM.get(jwsAlgorithm);
	}

	public String findDefaultCryptosuiteForJwsAlgorithm(String jwsAlgorithm) {
		List<String> foundCryptosuiteByJwsAlgorithm = findCryptosuitesForJwsAlgorithm(jwsAlgorithm);
		return foundCryptosuiteByJwsAlgorithm == null ? null : foundCryptosuiteByJwsAlgorithm.get(0);
	}
}
