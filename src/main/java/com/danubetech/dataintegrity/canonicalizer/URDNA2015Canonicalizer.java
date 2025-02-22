package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.util.SHAUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

public class URDNA2015Canonicalizer extends Canonicalizer {

    public URDNA2015Canonicalizer() {

        super(List.of("urdna2015"));
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

        String canonicalizedLdProofWithoutProofValues = dataIntegrityProofWithoutProofValues.normalize("urdna2015");
        String canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize("urdna2015");

        // construct the canonicalization result

        byte[] canonicalizationResult = new byte[64];
        System.arraycopy(SHAUtil.sha256(canonicalizedLdProofWithoutProofValues), 0, canonicalizationResult, 0, 32);
        System.arraycopy(SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof), 0, canonicalizationResult, 32, 32);

        return canonicalizationResult;
    }
}
