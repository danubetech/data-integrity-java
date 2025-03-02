package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class Ed25519Signature2020DataIntegritySuite extends DataIntegritySuite {

	Ed25519Signature2020DataIntegritySuite() {
		super(
				"Ed25519Signature2020",
				URI.create("https://w3id.org/security#Ed25519Signature2020"),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2020_V1, DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
