package com.danubetech.dataintegrity.signer;

import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.ParameterizedType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdSignerRegistry {

    public static final List<Class<? extends LdSigner<? extends DataIntegritySuite>>> LD_SIGNERS = List.of(
            RsaSignature2018LdSigner.class,
            Ed25519Signature2018LdSigner.class,
            Ed25519Signature2020LdSigner.class,
            JcsEd25519Signature2020LdSigner.class,
            EcdsaSecp256k1Signature2019LdSigner.class,
            EcdsaKoblitzSignature2016LdSigner.class,
            JcsEcdsaSecp256k1Signature2019LdSigner.class,
            BbsBlsSignature2020LdSigner.class,
            JsonWebSignature2020LdSigner.class,
            DataIntegrityProofLdSigner.class
    );

    private static final Map<String, Class<? extends LdSigner<? extends DataIntegritySuite>>> LD_SIGNERS_BY_DATA_INTEGRITY_SUITE_TERM;

    static {
        LD_SIGNERS_BY_DATA_INTEGRITY_SUITE_TERM = new HashMap<>();
        for (Class<? extends LdSigner<? extends DataIntegritySuite>> ldSignerClass : LD_SIGNERS) {
            Class<? extends DataIntegritySuite> dataIntegritySuiteClass = (Class<? extends DataIntegritySuite>) ((ParameterizedType) ldSignerClass.getGenericSuperclass()).getActualTypeArguments()[0];
            String term = DataIntegritySuites.findDataIntegritySuiteByClass(dataIntegritySuiteClass).getTerm();
            LD_SIGNERS_BY_DATA_INTEGRITY_SUITE_TERM.put(term, ldSignerClass);
        }
    }

    public static LdSigner<? extends DataIntegritySuite> getLdSignerByDataIntegritySuiteTerm(String dataIntegritySuiteTerm) {
        Class<? extends LdSigner<? extends DataIntegritySuite>> ldSignerClass = LD_SIGNERS_BY_DATA_INTEGRITY_SUITE_TERM.get(dataIntegritySuiteTerm);
        if (ldSignerClass == null) throw new IllegalArgumentException();
        LdSigner<? extends DataIntegritySuite> ldSigner;
        try {
            ldSigner = ldSignerClass.getConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }
        return ldSigner;
    }

    public static LdSigner<? extends DataIntegritySuite> getLdSignerByDataIntegritySuite(DataIntegritySuite dataIntegritySuite) {
        return getLdSignerByDataIntegritySuiteTerm(dataIntegritySuite.getTerm());
    }
}
