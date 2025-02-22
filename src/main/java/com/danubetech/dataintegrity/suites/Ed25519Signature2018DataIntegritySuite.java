package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;
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
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#ed25519"),
				List.of(KeyTypeName.Ed25519),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				List.of(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2018_V1, URI.create("https://www.w3.org/2018/credentials/v1"), LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
