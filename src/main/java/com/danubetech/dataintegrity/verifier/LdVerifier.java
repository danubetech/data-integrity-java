package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteVerifier;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import java.io.IOException;
import java.security.GeneralSecurityException;

public abstract class LdVerifier<DATAINTEGRITYSUITE extends DataIntegritySuite> {

    private final DATAINTEGRITYSUITE dataIntegritySuite;

    private ByteVerifier verifier;
    private Canonicalizer canonicalizer;

    protected LdVerifier(DATAINTEGRITYSUITE dataIntegritySuite, ByteVerifier verifier, Canonicalizer canonicalizer) {

        this.dataIntegritySuite = dataIntegritySuite;
        this.verifier = verifier;
        this.canonicalizer = canonicalizer;
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

    public abstract boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException;

    public boolean verify(JsonLDObject jsonLdObject, DataIntegrityProof dataIntegrityProof) throws IOException, GeneralSecurityException, JsonLDException {

        // check the proof object

        if (! this.getDataIntegritySuite().getTerm().equals(dataIntegrityProof.getType()))
            throw new GeneralSecurityException("Unexpected signature type: " + dataIntegrityProof.getType() + " is not " + this.getDataIntegritySuite().getTerm());

        // obtain the canonicalized document

        byte[] canonicalizationResult = this.getCanonicalizer().canonicalize(dataIntegrityProof, jsonLdObject);

        // verify

        boolean verify = this.verify(canonicalizationResult, dataIntegrityProof);

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

    public DataIntegritySuite getDataIntegritySuite() {
        return this.dataIntegritySuite;
    }

    /*
     * Getters and setters
     */

    public ByteVerifier getVerifier() {
        return this.verifier;
    }

    public void setVerifier(ByteVerifier verifier) {
        this.verifier = verifier;
    }

    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    public void setCanonicalizer(Canonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }
}
