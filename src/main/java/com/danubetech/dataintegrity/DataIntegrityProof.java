package com.danubetech.dataintegrity;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.jsonld.DataIntegrityKeywords;
import com.fasterxml.jackson.annotation.JsonCreator;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

import java.io.Reader;
import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class DataIntegrityProof extends JsonLDObject {

	public static final URI[] DEFAULT_JSONLD_CONTEXTS = { };
	public static final String[] DEFAULT_JSONLD_TYPES = { };
	public static final String DEFAULT_JSONLD_PREDICATE = DataIntegrityKeywords.JSONLD_TERM_PROOF;
	public static final DocumentLoader DEFAULT_DOCUMENT_LOADER = DataIntegrityContexts.DOCUMENT_LOADER;

	@JsonCreator
	public DataIntegrityProof() {
		super();
	}

	protected DataIntegrityProof(Map<String, Object> jsonObject) {
		super(jsonObject);
	}

	/*
	 * Factory methods
	 */

	public static class Builder<B extends Builder<B>> extends JsonLDObject.Builder<B> {

		private String cryptosuite;
		private Date created;
		private Date expires;
		private String domain;
		private String challenge;
		private String nonce;
		private URI verificationMethod;
		private String proofPurpose;
		private String previousProof;
		private String proofValue;
		private String jws;

		public Builder(DataIntegrityProof jsonLdObject) {
			super(jsonLdObject);
		}

		@Override
		public DataIntegrityProof build() {

			super.build();

			// add JSON-LD properties
			if (this.cryptosuite != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_CRYPTOSUITE, this.cryptosuite);
			if (this.created != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_CREATED, JsonLDUtils.dateToString(this.created));
			if (this.expires != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_EXPIRES, JsonLDUtils.dateToString(this.expires));
			if (this.domain != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_DOMAIN, this.domain);
			if (this.challenge != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_CHALLENGE, this.challenge);
			if (this.nonce != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_NONCE, this.nonce);
			if (this.verificationMethod != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_VERIFICATIONMETHOD, JsonLDUtils.uriToString(this.verificationMethod));
			if (this.proofPurpose != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_PROOFPURPOSE, this.proofPurpose);
			if (this.previousProof != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_PREVIOUSPROOF, this.previousProof);
			if (this.proofValue != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_PROOFVALUE, this.proofValue);
			if (this.jws != null) JsonLDUtils.jsonLdAdd(this.jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_JWS, this.jws);

			return (DataIntegrityProof) this.jsonLdObject;
		}

		public B cryptosuite(String cryptosuite) {
			this.cryptosuite = cryptosuite;
			return (B) this;
		}

		public B created(Date created) {
			this.created = created;
			return (B) this;
		}

		public B expires(Date expires) {
			this.expires = expires;
			return (B) this;
		}

		public B domain(String domain) {
			this.domain = domain;
			return (B) this;
		}

		public B challenge(String challenge) {
			this.challenge = challenge;
			return (B) this;
		}

		public B nonce(String nonce) {
			this.nonce = nonce;
			return (B) this;
		}

		public B verificationMethod(URI verificationMethod) {
			this.verificationMethod = verificationMethod;
			return (B) this;
		}

		public B proofPurpose(String proofPurpose) {
			this.proofPurpose = proofPurpose;
			return (B) this;
		}

		public B previousProof(String previousProof) {
			this.previousProof = previousProof;
			return (B) this;
		}

		public B proofValue(String proofValue) {
			this.proofValue = proofValue;
			return (B) this;
		}

		public B jws(String jws) {
			this.jws = jws;
			return (B) this;
		}
	}

	public static Builder<? extends Builder<?>> builder() {
		return new Builder<>(new DataIntegrityProof());
	}

	public static DataIntegrityProof fromJsonObject(Map<String, Object> jsonObject) {
		return new DataIntegrityProof(jsonObject);
	}

	public static DataIntegrityProof fromJsonLDObject(JsonLDObject jsonLDObject) { return fromJsonObject(jsonLDObject.getJsonObject()); }

	public static DataIntegrityProof fromJson(Reader reader) {
		return new DataIntegrityProof(readJson(reader));
	}

	public static DataIntegrityProof fromJson(String json) {
		return new DataIntegrityProof(readJson(json));
	}

	public static DataIntegrityProof fromMap(Map<String, Object> jsonObject) {
		return new DataIntegrityProof(jsonObject);
	}

	/*
	 * Adding, getting, and removing the JSON-LD object
	 */

	public static DataIntegrityProof getFromJsonLDObject(JsonLDObject jsonLdObject) {
		return JsonLDObject.getFromJsonLDObject(DataIntegrityProof.class, jsonLdObject);
	}

	public static List<DataIntegrityProof> getFromJsonLDObjectAsList(JsonLDObject jsonLdObject) {
		return JsonLDObject.getFromJsonLDObjectAsList(DataIntegrityProof.class, jsonLdObject);
	}

	public static void removeFromJsonLdObject(JsonLDObject jsonLdObject) {
		JsonLDObject.removeFromJsonLdObject(DataIntegrityProof.class, jsonLdObject);
	}

	/*
	 * Helper methods
	 */

	public static void removeLdProofValues(JsonLDObject jsonLdObject) {
		JsonLDUtils.jsonLdRemove(jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_PROOFVALUE);
		JsonLDUtils.jsonLdRemove(jsonLdObject, DataIntegrityKeywords.JSONLD_TERM_JWS);
		JsonLDUtils.jsonLdRemove(jsonLdObject, "signatureValue");
	}

	/*
	 * Getters
	 */

	public String getCryptosuite() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_CRYPTOSUITE);
	}

	public Date getCreated() {
		return JsonLDUtils.stringToDate(JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_CREATED));
	}

	public Date getExpires() {
		return JsonLDUtils.stringToDate(JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_EXPIRES));
	}

	public String getDomain() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_DOMAIN);
	}

	public String getChallenge() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_CHALLENGE);
	}

	public String getNonce() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_NONCE);
	}

	public URI getVerificationMethod() {
		return JsonLDUtils.stringToUri(JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_VERIFICATIONMETHOD));
	}

	public String getProofPurpose() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_PROOFPURPOSE);
	}

	public String getPreviousProof() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_PREVIOUSPROOF);
	}

	public String getProofValue() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_PROOFVALUE);
	}

	public String getJws() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), DataIntegrityKeywords.JSONLD_TERM_JWS);
	}
}
