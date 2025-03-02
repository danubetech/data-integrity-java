package com.danubetech.dataintegrity.suites;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class BbsBlsSignature2020DataIntegritySuite extends DataIntegritySuite {

	BbsBlsSignature2020DataIntegritySuite() {
		super(
				"BbsBlsSignature2020",
				URI.create("https://w3id.org/security#BbsBlsSignature2020"),
				Map.of(KeyTypeName.Bls12381G1, List.of(JWSAlgorithm.BBSPlus),
						KeyTypeName.Bls12381G2, List.of(JWSAlgorithm.BBSPlus)),
				List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1, DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
