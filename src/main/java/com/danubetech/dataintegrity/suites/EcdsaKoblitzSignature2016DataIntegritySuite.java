package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaKoblitzSignature2016DataIntegritySuite extends DataIntegritySuite {

	EcdsaKoblitzSignature2016DataIntegritySuite() {
		super(
				"EcdsaKoblitzSignature2016",
				URI.create("https://w3id.org/security#EcdsaKoblitzSignature2016"),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V1, DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
