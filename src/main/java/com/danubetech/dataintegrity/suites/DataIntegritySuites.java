package com.danubetech.dataintegrity.suites;

import com.danubetech.keyformats.jose.KeyTypeName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class DataIntegritySuites {

	private static final Logger log = LoggerFactory.getLogger(DataIntegritySuites.class);

	public static final RsaSignature2018DataIntegritySuite DATA_INTEGRITY_SUITE_RSASIGNATURE2018 = new RsaSignature2018DataIntegritySuite();
	public static final Ed25519Signature2018DataIntegritySuite DATA_INTEGRITY_SUITE_ED25519SIGNATURE2018 = new Ed25519Signature2018DataIntegritySuite();
	public static final Ed25519Signature2020DataIntegritySuite DATA_INTEGRITY_SUITE_ED25519SIGNATURE2020 = new Ed25519Signature2020DataIntegritySuite();
	public static final JcsEd25519Signature2020DataIntegritySuite DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020 = new JcsEd25519Signature2020DataIntegritySuite();
	public static final EcdsaSecp256k1Signature2019DataIntegritySuite DATA_INTEGRITY_SUITE_ECDSASECP256K1SIGNATURE2019 = new EcdsaSecp256k1Signature2019DataIntegritySuite();
	public static final EcdsaSecp256r1Signature2019DataIntegritySuite DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019 = new EcdsaSecp256r1Signature2019DataIntegritySuite();
	public static final EcdsaKoblitzSignature2016DataIntegritySuite DATA_INTEGRITY_SUITE_ECDSAKOBLITZSIGNATURE2016 = new EcdsaKoblitzSignature2016DataIntegritySuite();
	public static final JcsEcdsaSecp256k1Signature2019DataIntegritySuite DATA_INTEGRITY_SUITE_JCSECDSASECP256L1SIGNATURE2019 = new JcsEcdsaSecp256k1Signature2019DataIntegritySuite();
	public static final BbsBlsSignature2020DataIntegritySuite DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020 = new BbsBlsSignature2020DataIntegritySuite();
	public static final JsonWebSignature2020DataIntegritySuite DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020 = new JsonWebSignature2020DataIntegritySuite();
	public static final DataIntegrityProofDataIntegritySuite DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF = new DataIntegrityProofDataIntegritySuite();

	public static final List<? extends DataIntegritySuite> DATA_INTEGRITY_SUITES = List.of(
			DATA_INTEGRITY_SUITE_RSASIGNATURE2018,
			DATA_INTEGRITY_SUITE_ED25519SIGNATURE2018,
			DATA_INTEGRITY_SUITE_ED25519SIGNATURE2020,
			DATA_INTEGRITY_SUITE_JCSED25519SIGNATURE2020,
			DATA_INTEGRITY_SUITE_ECDSASECP256K1SIGNATURE2019,
			DATA_INTEGRITY_SUITE_ECDSASECP256R1SIGNATURE2019,
			DATA_INTEGRITY_SUITE_ECDSAKOBLITZSIGNATURE2016,
			DATA_INTEGRITY_SUITE_JCSECDSASECP256L1SIGNATURE2019,
			DATA_INTEGRITY_SUITE_BBSBLSSIGNATURE2020,
			DATA_INTEGRITY_SUITE_JSONWEBSIGNATURE2020,
			DATA_INTEGRITY_SUITE_DATAINTEGRITYPROOF
	);

	private static final Map<Class<? extends DataIntegritySuite>, DataIntegritySuite> DATA_INTEGRITY_SUITES_BY_DATA_INTEGRITY_SUITE_CLASS;
	private static final Map<String, DataIntegritySuite> DATA_INTEGRITY_SUITES_BY_TERM;
	private static final Map<KeyTypeName, List<DataIntegritySuite>> DATA_INTEGRITY_SUITES_BY_KEY_TYPE_NAME;

	static {
		DATA_INTEGRITY_SUITES_BY_DATA_INTEGRITY_SUITE_CLASS = new HashMap<>();
		for (DataIntegritySuite dataIntegritySuite : DATA_INTEGRITY_SUITES) {
			Class<? extends DataIntegritySuite> dataIntegritySuiteClass = dataIntegritySuite.getClass();
			DATA_INTEGRITY_SUITES_BY_DATA_INTEGRITY_SUITE_CLASS.put(dataIntegritySuiteClass, dataIntegritySuite);
		}
	}

	static {
		DATA_INTEGRITY_SUITES_BY_TERM = new HashMap<>();
		for (DataIntegritySuite dataIntegritySuite : DATA_INTEGRITY_SUITES) {
			String dataIntegritySuiteTerm = dataIntegritySuite.getTerm();
			DATA_INTEGRITY_SUITES_BY_TERM.put(dataIntegritySuiteTerm, dataIntegritySuite);
		}
	}

	static {
		DATA_INTEGRITY_SUITES_BY_KEY_TYPE_NAME = new HashMap<>();
		for (DataIntegritySuite dataIntegritySuite : DATA_INTEGRITY_SUITES) {
			Set<KeyTypeName> keyTypeNames = dataIntegritySuite.getJwsAlgorithmsByKeyTypeName().keySet();
			for (KeyTypeName keyTypeName : keyTypeNames) {
                List<DataIntegritySuite> dataIntegritySuitesList = DATA_INTEGRITY_SUITES_BY_KEY_TYPE_NAME.computeIfAbsent(keyTypeName, k -> new ArrayList<>());
                dataIntegritySuitesList.add(dataIntegritySuite);
			}
		}
	}

	public static DataIntegritySuite findDataIntegritySuiteByClass(Class<? extends DataIntegritySuite> clazz) {
		return DATA_INTEGRITY_SUITES_BY_DATA_INTEGRITY_SUITE_CLASS.get(clazz);
	}

	public static DataIntegritySuite findDataIntegritySuiteByTerm(String dataIntegritySuiteTerm) {
		return DATA_INTEGRITY_SUITES_BY_TERM.get(dataIntegritySuiteTerm);
	}

	public static List<DataIntegritySuite> findDataIntegritySuitesByKeyTypeName(KeyTypeName keyTypeName) {
		return DATA_INTEGRITY_SUITES_BY_KEY_TYPE_NAME.get(keyTypeName);
	}

	public static DataIntegritySuite findDefaultDataIntegritySuiteByKeyTypeName(KeyTypeName keyTypeName) {
		List<DataIntegritySuite> foundDataIntegritySuitesByKeyTypeName = findDataIntegritySuitesByKeyTypeName(keyTypeName);
		DataIntegritySuite dataIntegritySuite = foundDataIntegritySuitesByKeyTypeName == null ? null : foundDataIntegritySuitesByKeyTypeName.get(0);
		if (log.isDebugEnabled()) log.debug("Found default data integrity suite for key type " + keyTypeName.getValue() + ": " + dataIntegritySuite);
		return dataIntegritySuite;
	}
}
