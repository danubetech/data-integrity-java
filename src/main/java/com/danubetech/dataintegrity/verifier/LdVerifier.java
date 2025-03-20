package com.danubetech.dataintegrity.verifier;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteVerifier;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Objects;

public abstract class LdVerifier<DATAINTEGRITYSUITE extends DataIntegritySuite> {

    private static final Logger log = LoggerFactory.getLogger(LdVerifier.class);

    private final DATAINTEGRITYSUITE dataIntegritySuite;

    private ByteVerifier verifier;

    protected LdVerifier(DATAINTEGRITYSUITE dataIntegritySuite, ByteVerifier verifier) {
        this.dataIntegritySuite = dataIntegritySuite;
        this.verifier = verifier;
    }

    /**
     * @deprecated
     * Use LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm(dataIntegritySuiteTerm) instead.
     */
    @Deprecated
    public static LdVerifier<? extends DataIntegritySuite> ldVerifierForDataIntegritySuite(String dataIntegritySuiteTerm) {
        return LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm(dataIntegritySuiteTerm);
    }

    /**
     * @deprecated
     * Use LdVerifierRegistry.getLdVerifierByDataIntegritySuite(dataIntegritySuite) instead.
     */
    @Deprecated
    public static LdVerifier<? extends DataIntegritySuite> ldVerifierForDataIntegritySuite(DataIntegritySuite dataIntegritySuite) {
        return LdVerifierRegistry.getLdVerifierByDataIntegritySuite(dataIntegritySuite);
    }

    public boolean verify(JsonLDObject jsonLdObject, DataIntegrityProof dataIntegrityProof) throws IOException, GeneralSecurityException, JsonLDException {

        // check the proof object

        if (! this.getDataIntegritySuite().getTerm().equals(dataIntegrityProof.getType()))
            throw new GeneralSecurityException("Unexpected signature type: " + dataIntegrityProof.getType() + " is not " + this.getDataIntegritySuite().getTerm());

        // initialize

        this.initialize(dataIntegrityProof);

        // construct LD proof options

        DataIntegrityProof ldProofOptions = DataIntegrityProof.fromJson(dataIntegrityProof.toJson());
        if (ldProofOptions.getContexts() == null || ldProofOptions.getContexts().isEmpty()) {
            JsonLDUtils.jsonLdAdd(ldProofOptions, Keywords.CONTEXT, jsonLdObject.getContexts().stream().map(JsonLDUtils::uriToString).filter(Objects::nonNull).toList());
        }

        // obtain the canonicalized document

        Canonicalizer canonicalizer = this.getCanonicalizer(ldProofOptions);
        byte[] canonicalizationResult = canonicalizer.canonicalize(ldProofOptions, jsonLdObject);
        if (log.isDebugEnabled()) log.debug("Canonicalization result with {}: {}", canonicalizer.getClass().getSimpleName(), Hex.encodeHexString(canonicalizationResult));

        // verify

        boolean verify = this.verify(canonicalizationResult, ldProofOptions);
        if (log.isDebugEnabled()) log.debug("Verified data integrity proof: {} --> {}", dataIntegrityProof, verify);

        // done

        return verify;
    }

    public boolean verify(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // obtain the signature object

        DataIntegrityProof dataIntegrityProof = DataIntegrityProof.getFromJsonLDObject(jsonLdObject);
        if (dataIntegrityProof == null) return false;

        // done

        return this.verify(jsonLdObject, dataIntegrityProof);
    }

    public void initialize(DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

    }

    public abstract boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException;

    public abstract Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof);

    /*
     * Getters and setters
     */

    public DATAINTEGRITYSUITE getDataIntegritySuite() {
        return this.dataIntegritySuite;
    }

    public ByteVerifier getVerifier() {
        return this.verifier;
    }

    public void setVerifier(ByteVerifier verifier) {
        this.verifier = verifier;
    }
}
