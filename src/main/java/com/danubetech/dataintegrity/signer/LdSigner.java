package com.danubetech.dataintegrity.signer;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.crypto.ByteSigner;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public abstract class LdSigner<DATAINTEGRITYSUITE extends DataIntegritySuite> {

	private static final Logger log = LoggerFactory.getLogger(LdSigner.class);

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
	private URI capability;
	private List<URI> capabilityChains;
	private String capabilityAction;

	protected LdSigner(DATAINTEGRITYSUITE dataIntegritySuite, ByteSigner signer) {
		this.dataIntegritySuite = dataIntegritySuite;
		this.signer = signer;
	}

	protected LdSigner(DATAINTEGRITYSUITE dataIntegritySuite, ByteSigner signer, String cryptosuite, Date created, Date expires, String domain, String challenge, String nonce, URI verificationMethod, String proofPurpose, String previousProof, URI capability, List<URI> capabilityChains, String capabilityAction) {
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
		this.capability = capability;
		this.capabilityChains = capabilityChains;
		this.capabilityAction = capabilityAction;
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

	public DataIntegrityProof sign(JsonLDObject jsonLdObject, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException {

		// build the base proof object

		DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofOptionsBuilder = DataIntegrityProof.builder()
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
				.capability(this.getCapability())
				.capabilityChains(this.getCapabilityChains())
				.capabilityAction(this.getCapabilityAction());

		// initialize

		this.initialize(ldProofOptionsBuilder);

		// construct LD proof options

		DataIntegrityProof ldProofOptions = ldProofOptionsBuilder.build();
		if (ldProofOptions.getContexts() == null || ldProofOptions.getContexts().isEmpty()) {
			JsonLDUtils.jsonLdAdd(ldProofOptions, Keywords.CONTEXT, jsonLdObject.getContexts().stream().map(JsonLDUtils::uriToString).filter(Objects::nonNull).toList());
		}
		if (log.isDebugEnabled()) log.debug("Data integrity proof options: {}", ldProofOptions);

		// add missing context(s)

		this.loadMissingContext(jsonLdObject);

		// obtain the canonicalized document

		Canonicalizer canonicalizer = this.getCanonicalizer(ldProofOptions);
		byte[] canonicalizationResult = canonicalizer.canonicalize(ldProofOptions, jsonLdObject);
		if (log.isDebugEnabled()) log.debug("Canonicalization result with {}: {}", canonicalizer.getClass().getSimpleName(), Hex.encodeHexString(canonicalizationResult));

		// sign

		DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder = DataIntegrityProof.builder()
				.base(ldProofOptions)
				.defaultContexts(defaultContexts);

		this.sign(ldProofBuilder, canonicalizationResult);

		DataIntegrityProof dataIntegrityProof = ldProofBuilder.build();
		if (log.isDebugEnabled()) log.debug("Signed data integrity proof: {}", dataIntegrityProof);

		// add proof to JSON-LD

		if (addToJsonLdObject) dataIntegrityProof.addToJsonLDObject(jsonLdObject);

		// done

		return dataIntegrityProof;
	}

	public DataIntegrityProof sign(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

		return this.sign(jsonLdObject, true, false);
	}

	public void initialize(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder) throws GeneralSecurityException {

	}

	public abstract Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof);

	public abstract void sign(DataIntegrityProof.Builder<? extends DataIntegrityProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException;

	/*
	 * Helper methods
	 */

	private void loadMissingContext(JsonLDObject jsonLDObject){
		if (this.getDataIntegritySuite().getSupportedJsonLDContexts().stream().noneMatch(jsonLDObject.getContexts()::contains)) {
			URI missingJsonLDContext = this.getDataIntegritySuite().getDefaultSupportedJsonLDContext();
			if (missingJsonLDContext != null) {
				JsonLDUtils.jsonLdAddAsJsonArray(jsonLDObject, Keywords.CONTEXT, JsonLDUtils.uriToString(missingJsonLDContext));
			}
		}
	}

	/*
	 * Getters and setters
	 */

	public DATAINTEGRITYSUITE getDataIntegritySuite() {
		return this.dataIntegritySuite;
	}

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

	public URI getCapability() {
		return capability;
	}

	public void setCapability(URI capability) {
		this.capability = capability;
	}

	public List<URI> getCapabilityChains() {
		return capabilityChains;
	}

	public void setCapabilityChains(List<URI> capabilityChains) {
		this.capabilityChains = capabilityChains;
	}

	public String getCapabilityAction() {
		return capabilityAction;
	}

	public void setCapabilityAction(String capabilityAction) {
		this.capabilityAction = capabilityAction;
	}
}
