package com.danubetech.dataintegrity.canonicalizer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Canonicalizers {

	public static final JCSSHA256Canonicalizer CANONICALIZER_JCSCANONICALIZER = new JCSSHA256Canonicalizer();
	public static final URDNA2015SHA256Canonicalizer CANONICALIZER_URDNA2015SHA256CANONICALIZER = new URDNA2015SHA256Canonicalizer();
	public static final URDNA2015SHA384Canonicalizer CANONICALIZER_URDNA2015SHA384CANONICALIZER = new URDNA2015SHA384Canonicalizer();

	public static final List<? extends Canonicalizer> CANONICALIZERS = List.of(
			CANONICALIZER_JCSCANONICALIZER,
			CANONICALIZER_URDNA2015SHA256CANONICALIZER,
			CANONICALIZER_URDNA2015SHA384CANONICALIZER
	);

	private static final Map<Class<? extends Canonicalizer>, Canonicalizer> CANONICALIZERS_BY_CANONICALIZER_CLASS;
	private static final Map<String, List<Canonicalizer>> CANONICALIZERS_BY_ALGORITHM;

	static {
		CANONICALIZERS_BY_CANONICALIZER_CLASS = new HashMap<>();
		for (Canonicalizer canonicalizer : CANONICALIZERS) {
			Class<? extends Canonicalizer> canonicalizerClass = canonicalizer.getClass();
			CANONICALIZERS_BY_CANONICALIZER_CLASS.put(canonicalizerClass, canonicalizer);
		}
	}

	static {
		CANONICALIZERS_BY_ALGORITHM = new HashMap<>();
		for (Canonicalizer canonicalizer : CANONICALIZERS) {
			List<String> algorithms = canonicalizer.getAlgorithms();
			for (String algorithm : algorithms) {
                List<Canonicalizer> canonicalizersList = CANONICALIZERS_BY_ALGORITHM.computeIfAbsent(algorithm, k -> new ArrayList<>());
                canonicalizersList.add(canonicalizer);
			}
		}
	}

	public static Canonicalizer findCanonicalizerByClass(Class<? extends Canonicalizer> clazz) {
		return CANONICALIZERS_BY_CANONICALIZER_CLASS.get(clazz);
	}

	public static List<Canonicalizer> findCanonicalizersByAlgorithm(String algorithm) {
		return CANONICALIZERS_BY_ALGORITHM.get(algorithm);
	}

	public static Canonicalizer findDefaultCanonicalizerByAlgorithm(String algorithm) {
		List<Canonicalizer> foundCanonicalizersByKeyTypeName = findCanonicalizersByAlgorithm(algorithm);
		return foundCanonicalizersByKeyTypeName == null ? null : foundCanonicalizersByKeyTypeName.get(0);
	}
}
