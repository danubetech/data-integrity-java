package com.danubetech.dataintegrity.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.dataintegrity.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class JcsEd25519Signature2020DataIntegritySuite extends DataIntegritySuite {

	JcsEd25519Signature2020DataIntegritySuite() {

		super(
				"JcsEd25519Signature2020",
				URI.create("https://w3id.org/security#JcsEd25519Signature2020"),
				URI.create("https://tools.ietf.org/html/draft-rundgren-json-canonicalization-scheme-16"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#ed25519"),
				List.of(KeyTypeName.Ed25519),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				Arrays.asList(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SUITES_ED25519_2020_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
