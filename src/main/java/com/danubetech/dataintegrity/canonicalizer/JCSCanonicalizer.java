package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public abstract class JCSCanonicalizer extends Canonicalizer {

	private static final Logger log = LoggerFactory.getLogger(JCSCanonicalizer.class);

	public JCSCanonicalizer() {
		super(List.of("jcs"));
	}

	public abstract int hashLength();
	public abstract byte[] hash(byte[] input) throws GeneralSecurityException;

	@Override
	public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException {

		return new JsonCanonicalizer(jsonLDObject.toJson()).getEncodedString();
	}

	@Override
	public byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

		// construct the LD object without proof

		JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
				.base(jsonLdObject)
				.build();
		DataIntegrityProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

		// construct the LD proof options without proof values

		DataIntegrityProof dataIntegrityProofWithoutProofValues = DataIntegrityProof.builder()
				.base(dataIntegrityProof)
				.defaultContexts(false)
				.build();
		DataIntegrityProof.removeLdProofValues(dataIntegrityProofWithoutProofValues);

		// canonicalize the LD object and LD proof options

		String canonicalizedJsonLdObjectWithoutProof = this.canonicalize(jsonLdObjectWithoutProof);
		byte[] canonicalizedJsonLdObjectWithoutProofHash = this.hash(canonicalizedJsonLdObjectWithoutProof.getBytes(StandardCharsets.UTF_8));
		if (log.isDebugEnabled()) log.debug("Canonicalized LD object without proof: {}", canonicalizedJsonLdObjectWithoutProof);
		if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD object without proof: {}", Hex.encodeHexString(canonicalizedJsonLdObjectWithoutProofHash));

		String canonicalizedLdProofWithoutProofValues = this.canonicalize(dataIntegrityProofWithoutProofValues);
		byte[] canonicalizedLdProofWithoutProofValuesHash = this.hash(canonicalizedLdProofWithoutProofValues.getBytes(StandardCharsets.UTF_8));
		if (log.isDebugEnabled()) log.debug("Canonicalized LD proof without proof value: {}", canonicalizedLdProofWithoutProofValues);
		if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD proof without proof value: {}", Hex.encodeHexString(canonicalizedLdProofWithoutProofValuesHash));

		// construct the canonicalization result

		byte[] canonicalizationResult = new byte[this.hashLength()*2];
		System.arraycopy(canonicalizedLdProofWithoutProofValuesHash, 0, canonicalizationResult, 0, this.hashLength());
		System.arraycopy(canonicalizedJsonLdObjectWithoutProofHash, 0, canonicalizationResult, this.hashLength(), this.hashLength());

		return canonicalizationResult;
	}
}
