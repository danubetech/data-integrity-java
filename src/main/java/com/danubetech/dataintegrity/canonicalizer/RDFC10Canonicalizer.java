package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.jsonld.lang.Keywords;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.canon.RdfCanonicalizer;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

public abstract class RDFC10Canonicalizer extends Canonicalizer {

    public RDFC10Canonicalizer() {
        super(List.of("RDFC-1.0"));
    }

    public abstract int hashLength();
    public abstract byte[] hash(byte[] input) throws GeneralSecurityException;

    @Override
    public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException {

        RdfDataset rdfDataset = jsonLDObject.toDataset();
        Collection<RdfNQuad> rdfNQuads = RdfCanonicalizer.canonicalize(rdfDataset.toList());
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

        dataIntegrityProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
        String canonicalizedLdProofWithoutProofValues = this.canonicalize(dataIntegrityProofWithoutProofValues);

        // hashing

        byte[] canonicalizedJsonLdObjectWithoutProofHash = this.hash(canonicalizedJsonLdObjectWithoutProof.getBytes(StandardCharsets.UTF_8));
        byte[] canonicalizedLdProofWithoutProofValuesHash = this.hash(canonicalizedLdProofWithoutProofValues.getBytes(StandardCharsets.UTF_8));

        // construct the canonicalization result

        byte[] canonicalizationResult = new byte[this.hashLength()*2];
        System.arraycopy(canonicalizedLdProofWithoutProofValuesHash, 0, canonicalizationResult, 0, this.hashLength());
        System.arraycopy(canonicalizedJsonLdObjectWithoutProofHash, 0, canonicalizationResult, this.hashLength(), this.hashLength());

        return canonicalizationResult;
    }
}
