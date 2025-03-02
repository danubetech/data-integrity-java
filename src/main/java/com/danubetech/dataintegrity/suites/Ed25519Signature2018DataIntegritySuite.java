package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class Ed25519Signature2018DataIntegritySuite extends DataIntegritySuite {

	Ed25519Signature2018DataIntegritySuite() {
		super(
				"Ed25519Signature2018",
				URI.create("https://w3id.org/security#Ed25519Signature2018"),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2018_V1, URI.create("https://www.w3.org/2018/credentials/v1"), DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
