package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.util.SHAUtil;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import io.setl.rdf.normalization.RdfNormalize;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class URDNA2015SHA256Canonicalizer extends Canonicalizer {

	private static final Logger log = LoggerFactory.getLogger(RDFC10Canonicalizer.class);

	public static final URDNA2015SHA256Canonicalizer INSTANCE = new URDNA2015SHA256Canonicalizer();

	public URDNA2015SHA256Canonicalizer() {
		super(List.of("urdna2015"));
	}

	public static URDNA2015SHA256Canonicalizer getInstance() {
		return INSTANCE;
	}

	@Override
	public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException, NoSuchAlgorithmException {

		RdfDataset rdfDataset = jsonLDObject.toDataset();
		rdfDataset = RdfNormalize.normalize(rdfDataset, "urdna2015");
		StringWriter stringWriter = new StringWriter();
		NQuadsWriter nQuadsWriter = new NQuadsWriter(stringWriter);
		nQuadsWriter.write(rdfDataset);
		return stringWriter.getBuffer().toString();
	}

	@Override
	public byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

		// construct the LD object without proof

		JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
				.base(jsonLdObject)
				.build();
		jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
		DataIntegrityProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

		// construct the LD proof without proof values

		DataIntegrityProof dataIntegrityProofWithoutProofValues = DataIntegrityProof.builder()
				.base(dataIntegrityProof)
				.defaultContexts(false)
				.build();
		dataIntegrityProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
		DataIntegrityProof.removeLdProofValues(dataIntegrityProofWithoutProofValues);

		// canonicalize the LD object and LD proof options

		jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
		String canonicalizedJsonLdObjectWithoutProof = this.canonicalize(jsonLdObjectWithoutProof);
		byte[] canonicalizedJsonLdObjectWithoutProofHash = SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof);
		if (log.isDebugEnabled()) log.debug("Canonicalized LD object without proof: {}", canonicalizedJsonLdObjectWithoutProof);
		if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD object without proof: {}", Hex.encodeHexString(canonicalizedJsonLdObjectWithoutProofHash));

		dataIntegrityProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
		String canonicalizedLdProofWithoutProofValues = this.canonicalize(dataIntegrityProofWithoutProofValues);
		byte[] canonicalizedLdProofWithoutProofValuesHash = SHAUtil.sha256(canonicalizedLdProofWithoutProofValues);
		if (log.isDebugEnabled()) log.debug("Canonicalized LD proof without proof value: {}", canonicalizedLdProofWithoutProofValues);
		if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD proof without proof value: {}", Hex.encodeHexString(canonicalizedLdProofWithoutProofValuesHash));

		// construct the canonicalization result

		byte[] canonicalizationResult = new byte[64];
		System.arraycopy(canonicalizedLdProofWithoutProofValuesHash, 0, canonicalizationResult, 0, 32);
		System.arraycopy(canonicalizedJsonLdObjectWithoutProofHash, 0, canonicalizationResult, 32, 32);

		return canonicalizationResult;
	}
}
