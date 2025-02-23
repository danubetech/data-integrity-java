package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaSecp256K1Signature2019DataIntegritySuite extends DataIntegritySuite {

	EcdsaSecp256K1Signature2019DataIntegritySuite() {
		super(
				"EcdsaSecp256k1Signature2019",
				URI.create("https://w3id.org/security#EcdsaSecp256k1Signature2019"),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_SECP256K1_2019_V1, URI.create("https://www.w3.org/2018/credentials/v1"), LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
