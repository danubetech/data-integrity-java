package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.canon.RdfCanonicalizer;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
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
import java.util.Collection;
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

        RdfDataset rdfDataset = jsonLDObject.toDataset();
        RdfCanonicalizer rdfCanonicalizer = RdfCanonicalizer.newInstance(rdfDataset.toList());
        Collection<RdfNQuad> rdfNQuads = rdfCanonicalizer.canonicalize();
        StringWriter stringWriter = new StringWriter();
        NQuadsWriter nQuadsWriter = new NQuadsWriter(stringWriter);
        for (RdfNQuad rdfNQuad : rdfNQuads) nQuadsWriter.write(rdfNQuad);
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
