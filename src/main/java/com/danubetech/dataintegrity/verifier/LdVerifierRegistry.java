package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.ParameterizedType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdVerifierRegistry {

    public static final List<Class<? extends LdVerifier<? extends DataIntegritySuite>>> LD_VERIFIERS = List.of(
            RsaSignature2018LdVerifier.class,
            Ed25519Signature2018LdVerifier.class,
            Ed25519Signature2020LdVerifier.class,
            JcsEd25519Signature2020LdVerifier.class,
            EcdsaSecp256k1Signature2019LdVerifier.class,
            EcdsaKoblitzSignature2016LdVerifier.class,
            JcsEcdsaSecp256k1Signature2019LdVerifier.class,
            BbsBlsSignature2020LdVerifier.class,
            JsonWebSignature2020LdVerifier.class,
            DataIntegrityProofLdVerifier.class
    );

    private static final Map<String, Class<? extends LdVerifier<? extends DataIntegritySuite>>> LD_VERIFIERS_BY_DATA_INTEGRITY_SUITE_TERM;

    static {
        LD_VERIFIERS_BY_DATA_INTEGRITY_SUITE_TERM = new HashMap<>();
        for (Class<? extends LdVerifier<? extends DataIntegritySuite>> ldVerifierClass : LD_VERIFIERS) {
            Class<? extends DataIntegritySuite> dataIntegritySuiteClass = (Class<? extends DataIntegritySuite>) ((ParameterizedType) ldVerifierClass.getGenericSuperclass()).getActualTypeArguments()[0];
            String term = DataIntegritySuites.findDataIntegritySuiteByClass(dataIntegritySuiteClass).getTerm();
            LD_VERIFIERS_BY_DATA_INTEGRITY_SUITE_TERM.put(term, ldVerifierClass);
        }
    }

    public static LdVerifier<? extends DataIntegritySuite> getLdVerifierByDataIntegritySuiteTerm(String dataInegritySuiteTerm) {
        Class<? extends LdVerifier<? extends DataIntegritySuite>> ldVerifierClass = LD_VERIFIERS_BY_DATA_INTEGRITY_SUITE_TERM.get(dataInegritySuiteTerm);
        if (ldVerifierClass == null) throw new IllegalArgumentException();
        LdVerifier<? extends DataIntegritySuite> ldVerifier;
        try {
            ldVerifier = ldVerifierClass.getConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
        return ldVerifier;
    }

    public static LdVerifier<? extends DataIntegritySuite> getLdVerifierByDataIntegritySuite(DataIntegritySuite dataIntegritySuite) {
        return getLdVerifierByDataIntegritySuiteTerm(dataIntegritySuite.getTerm());
    }
}
