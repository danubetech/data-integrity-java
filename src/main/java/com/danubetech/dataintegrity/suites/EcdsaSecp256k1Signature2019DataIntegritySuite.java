package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaSecp256k1Signature2019DataIntegritySuite extends DataIntegritySuite {

	EcdsaSecp256k1Signature2019DataIntegritySuite() {
		super(
				"EcdsaSecp256k1Signature2019",
				URI.create("https://w3id.org/security#EcdsaSecp256k1Signature2019"),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_SECP256K1_2019_V1, DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3, DataIntegrityContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_V1));
	}
}
