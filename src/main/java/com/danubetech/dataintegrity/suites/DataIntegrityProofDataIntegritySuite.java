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
import java.util.stream.Collectors;

public class DataIntegrityProofDataIntegritySuite extends DataIntegritySuite {

	private static final Map<String, Canonicalizer> CANONICALIZERS_BY_CRYPTOSUITE = Map.of(
			"eddsa-rdfc-2022", RDFC10Canonicalizer.getInstance(),
			"eddsa-jcs-2022", JCSCanonicalizer.getInstance(),
			"ecdsa-rdfc-2019", RDFC10Canonicalizer.getInstance(),
			"ecdsa-jcs-2019", JCSCanonicalizer.getInstance(),
			"schnorr-secp256k1-rdfc-2025", RDFC10Canonicalizer.getInstance(),
			"schnorr-secp256k1-jcs-2025", JCSCanonicalizer.getInstance()
	);

	private static final Map<String, List<String>> CRYPTOSUITES_BY_JWS_ALGORITHM = Map.of(
			JWSAlgorithm.EdDSA, List.of("eddsa-rdfc-2022", "eddsa-jcs-2022"),
			JWSAlgorithm.ES256K, List.of("ecdsa-rdfc-2019", "ecdsa-jcs-2019"),
			JWSAlgorithm.ES256KS, List.of("schnorr-secp256k1-rdfc-2025", "schnorr-secp256k1-jcs-2025"),
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
                List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2));
	}

	@Override
	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName, String cryptosuite) {
		List<String> jwsAlgorithms = super.findJwsAlgorithmsForKeyTypeName(keyTypeName, cryptosuite);
		if (cryptosuite != null) jwsAlgorithms = jwsAlgorithms.stream().filter(jwsAlgorithm -> this.findCryptosuitesByJwsAlgorithm(jwsAlgorithm).contains(cryptosuite)).collect(Collectors.toList());
		return jwsAlgorithms;
	}

	public Canonicalizer findCanonicalizerByCryptosuite(String cryptosuite) {
		return CANONICALIZERS_BY_CRYPTOSUITE.get(cryptosuite);
	}

	public List<String> findCryptosuitesByJwsAlgorithm(String jwsAlgorithm) {
		return CRYPTOSUITES_BY_JWS_ALGORITHM.get(jwsAlgorithm);
	}

	public String findDefaultCryptosuiteByJwsAlgorithm(String jwsAlgorithm) {
		List<String> foundCryptosuiteByJwsAlgorithm = findCryptosuitesByJwsAlgorithm(jwsAlgorithm);
		return foundCryptosuiteByJwsAlgorithm == null ? null : foundCryptosuiteByJwsAlgorithm.get(0);
	}
}
