package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class RsaSignature2018DataIntegritySuite extends DataIntegritySuite {

	RsaSignature2018DataIntegritySuite() {
		super(
				"RsaSignature2018",
				URI.create("https://w3id.org/security#RsaSignature2018"),
				Map.of(KeyTypeName.RSA, List.of(JWSAlgorithm.RS256)),
				List.of(URI.create("https://www.w3.org/2018/credentials/v1"), DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
