package com.danubetech.dataintegrity.signer;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;

public abstract class LdSigner<DATAINTEGRITYSUITE extends DataIntegritySuite> {

    private final DATAINTEGRITYSUITE dataIntegritySuite;

    private ByteSigner signer;

    private String cryptosuite;
    private Date created;
    private Date expires;
    private String domain;
    private String challenge;
    private String nonce;
    private URI verificationMethod;
    private String proofPurpose;
    private String previousProof;

    protected LdSigner(DATAINTEGRITYSUITE dataIntegritySuite, ByteSigner signer) {
        this.dataIntegritySuite = dataIntegritySuite;
        this.signer = signer;
    }

    protected LdSigner(DATAINTEGRITYSUITE dataIntegritySuite, ByteSigner signer, String cryptosuite, Date created, Date expires, String domain, String challenge, String nonce, URI verificationMethod, String proofPurpose, String previousProof) {
        this.dataIntegritySuite = dataIntegritySuite;
        this.signer = signer;
        this.cryptosuite = cryptosuite;
        this.created = created;
        this.expires = expires;
        this.domain = domain;
        this.challenge = challenge;
        this.nonce = nonce;
        this.verificationMethod = verificationMethod;
        this.proofPurpose = proofPurpose;
    }

    /**
     * @deprecated
     * Use LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(dataIntegritySuiteTerm) instead.
     */
    @Deprecated
    public static LdSigner<? extends DataIntegritySuite> ldSignerForDataIntegritySuite(String dataIntegritySuiteTerm) {
        return LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(dataIntegritySuiteTerm);
    }

    /**
     * @deprecated
     * Use LdSignerRegistry.getLdSignerByDataIntegritySuite(dataIntegritySuite) instead.
     */
    @Deprecated
    public static LdSigner<? extends DataIntegritySuite> ldSignerForDataIntegritySuite(DataIntegritySuite dataIntegritySuite) {
        return LdSignerRegistry.getLdSignerByDataIntegritySuite(dataIntegritySuite);
    }

    public abstract void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException;

    public DataIntegrityProof sign(JsonLDObject jsonLdObject, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException {

        // build the base proof object

        DataIntegrityProof dataIntegrityProof = DataIntegrityProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .type(this.getDataIntegritySuite().getTerm())
                .cryptosuite(this.getCryptosuite())
                .created(this.getCreated())
                .expires(this.getExpires())
                .domain(this.getDomain())
                .challenge(this.getChallenge())
                .nonce(this.getNonce())
                .verificationMethod(this.getVerificationMethod())
                .proofPurpose(this.getProofPurpose())
                .previousProof(this.getPreviousProof())
                .build();

        // obtain the canonicalized document

        byte[] canonicalizationResult = this.getCanonicalizer().canonicalize(dataIntegrityProof, jsonLdObject);

        // sign

        DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder = DataIntegrityProof.builder()
                .base(dataIntegrityProof)
                .defaultContexts(defaultContexts);
        this.sign(ldProofBuilder, canonicalizationResult);

        dataIntegrityProof = ldProofBuilder.build();

        // add proof to JSON-LD

        if (addToJsonLdObject) dataIntegrityProof.addToJsonLDObject(jsonLdObject);
        loadMissingContext(jsonLdObject);

        // done

        return dataIntegrityProof;
    }

    private void loadMissingContext(JsonLDObject jsonLDObject){
        if (this.getDataIntegritySuite().getSupportedJsonLDContexts().stream().noneMatch(jsonLDObject.getContexts()::contains)) {
            URI missingJsonLDContext = this.getDataIntegritySuite().getDefaultSupportedJsonLDContext();
            if (missingJsonLDContext != null) {
                JsonLDUtils.jsonLdAddAsJsonArray(jsonLDObject, Keywords.CONTEXT, JsonLDUtils.uriToString(missingJsonLDContext));
            }
        }
    }

    public DataIntegrityProof sign(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {
        return this.sign(jsonLdObject, true, false);
    }

    public DataIntegritySuite getDataIntegritySuite() {
        return this.dataIntegritySuite;
    }

    public abstract Canonicalizer getCanonicalizer();

    /*
     * Getters and setters
     */

    public ByteSigner getSigner() {
        return this.signer;
    }

    public void setSigner(ByteSigner signer) {
        this.signer = signer;
    }

    public String getCryptosuite() {
        return cryptosuite;
    }

    public void setCryptosuite(String cryptosuite) {
        this.cryptosuite = cryptosuite;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public Date getExpires() {
        return expires;
    }

    public void setExpires(Date expires) {
        this.expires = expires;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public URI getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(URI verificationMethod) {
        this.verificationMethod = verificationMethod;
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public void setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
    }

    public String getPreviousProof() {
        return previousProof;
    }

    public void setPreviousProof(String previousProof) {
        this.previousProof = previousProof;
    }
}
