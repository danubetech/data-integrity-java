package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.rdf.api.RdfConsumerException;
import com.apicatalog.rdf.api.RdfQuadConsumer;
import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.nquads.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public abstract class RDFC10Canonicalizer extends Canonicalizer {

    private static final Logger log = LoggerFactory.getLogger(RDFC10Canonicalizer.class);

    public RDFC10Canonicalizer() {
        super(List.of("RDFC-1.0"));
    }

    public abstract String hashAlgorithm();
    public abstract int hashLength();
    public abstract byte[] hash(byte[] input) throws GeneralSecurityException;

    @Override
    public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException {
        RdfCanon rdfCanon = RdfCanon.create(this.hashAlgorithm());
        StringWriter stringWriter = new StringWriter();
        RdfQuadConsumer nQuadsWriter = new NQuadsWriter(stringWriter);

        try {
            jsonLDObject.toRdfApi().provide(rdfCanon);
            rdfCanon.provide(nQuadsWriter);
        } catch (RdfConsumerException ex) {
            throw new IOException("Cannot consume RDF: " + ex.getMessage(), ex);
        } catch (JsonLdError ex) {
            throw new JsonLDException(ex);
        }

        return stringWriter.getBuffer().toString();
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
                .build();
        DataIntegrityProof.removeLdProofValues(dataIntegrityProofWithoutProofValues);

        // canonicalize the LD object and LD proof options

        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        String canonicalizedJsonLdObjectWithoutProof = this.canonicalize(jsonLdObjectWithoutProof);
        byte[] canonicalizedJsonLdObjectWithoutProofHash = this.hash(canonicalizedJsonLdObjectWithoutProof.getBytes(StandardCharsets.UTF_8));
        if (log.isDebugEnabled()) log.debug("Canonicalized LD object without proof: {}", canonicalizedJsonLdObjectWithoutProof);
        if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD object without proof: {}", Hex.encodeHexString(canonicalizedJsonLdObjectWithoutProofHash));

        dataIntegrityProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
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
