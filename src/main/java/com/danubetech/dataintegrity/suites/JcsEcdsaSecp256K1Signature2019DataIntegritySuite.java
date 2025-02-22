package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class JcsEcdsaSecp256K1Signature2019DataIntegritySuite extends DataIntegritySuite {

	JcsEcdsaSecp256K1Signature2019DataIntegritySuite() {

		super(
				"JcsEcdsaSecp256k1Signature2019",
				URI.create("https://w3id.org/security#JcsEcdsaSecp256k1Signature2019"),
				URI.create("https://tools.ietf.org/html/draft-rundgren-json-canonicalization-scheme-16"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#secp256k1"),
				List.of(KeyTypeName.secp256k1),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_SECP256K1_2019_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
