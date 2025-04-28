package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaSecp384r1Signature2019DataIntegritySuite extends DataIntegritySuite {

	EcdsaSecp384r1Signature2019DataIntegritySuite() {
		super(
				"EcdsaSecp384r1Signature2019",
				URI.create("https://w3id.org/security#EcdsaSecp384r1Signature2019"),
				Map.of(KeyTypeName.P_384, List.of(JWSAlgorithm.ES384)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3, DataIntegrityContexts.JSONLD_CONTEXT_W3C_2018_CREDENTIALS_V1));
	}
}
