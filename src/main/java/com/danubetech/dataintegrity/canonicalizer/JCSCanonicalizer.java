package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.util.SHAUtil;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

public class JCSCanonicalizer extends Canonicalizer {

    public JCSCanonicalizer() {

        super(List.of("jcs"));
    }

    @Override
    public byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD proof without proof values

        DataIntegrityProof dataIntegrityProofWithoutProofValues = DataIntegrityProof.builder()
                .base(dataIntegrityProof)
                .defaultContexts(false)
                .build();
        DataIntegrityProof.removeLdProofValues(dataIntegrityProofWithoutProofValues);

        // construct the LD object with proof without proof values

        JsonLDObject jsonLdObjectWithProofWithoutProofValues = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
        DataIntegrityProof.removeFromJsonLdObject(jsonLdObjectWithProofWithoutProofValues);
        dataIntegrityProofWithoutProofValues.addToJsonLDObject(jsonLdObjectWithProofWithoutProofValues);

        // canonicalize the LD object

        String canonicalizedJsonLdObjectWithProofWithoutProofValues = new JsonCanonicalizer(jsonLdObjectWithProofWithoutProofValues.toJson()).getEncodedString();

        // construct the canonicalization result

        byte[] canonicalizationResult = SHAUtil.sha256(canonicalizedJsonLdObjectWithProofWithoutProofValues);
        return canonicalizationResult;
    }
}
