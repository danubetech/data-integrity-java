package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.canon.RdfCanonicalizer;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.util.SHAUtil;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.List;

public class RDFC10Canonicalizer extends Canonicalizer {

    private static final RDFC10Canonicalizer INSTANCE = new RDFC10Canonicalizer();

    public RDFC10Canonicalizer() {
        super(List.of("RDFC-1.0"));
    }

    public static RDFC10Canonicalizer getInstance() {
        return INSTANCE;
    }

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

        // construct the LD proof without proof values

        DataIntegrityProof dataIntegrityProofWithoutProofValues = DataIntegrityProof.builder()
                .base(dataIntegrityProof)
                .defaultContexts(true)
                .build();
        DataIntegrityProof.removeLdProofValues(dataIntegrityProofWithoutProofValues);

        // construct the LD object without proof

        JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        DataIntegrityProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // canonicalize the LD proof and LD object

        String canonicalizedLdProofWithoutProofValues = this.canonicalize(dataIntegrityProofWithoutProofValues);
        String canonicalizedJsonLdObjectWithoutProof = this.canonicalize(jsonLdObjectWithoutProof);

        // construct the canonicalization result

        byte[] canonicalizationResult = new byte[64];
        System.arraycopy(SHAUtil.sha256(canonicalizedLdProofWithoutProofValues), 0, canonicalizationResult, 0, 32);
        System.arraycopy(SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof), 0, canonicalizationResult, 32, 32);

        return canonicalizationResult;
    }
}
