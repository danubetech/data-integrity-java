package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.util.SHAUtil;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

public class JCSCanonicalizer extends Canonicalizer {

    private static final JCSCanonicalizer INSTANCE = new JCSCanonicalizer();

    public JCSCanonicalizer() {
        super(List.of("jcs"));
    }

    public static JCSCanonicalizer getInstance() {
        return INSTANCE;
    }

    @Override
    public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException {

        return new JsonCanonicalizer(jsonLDObject.toJson()).getEncodedString();
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

        String canonicalizedJsonLdObjectWithProofWithoutProofValues = this.canonicalize(jsonLdObjectWithProofWithoutProofValues);

        // construct the canonicalization result

        byte[] canonicalizationResult = SHAUtil.sha256(canonicalizedJsonLdObjectWithProofWithoutProofValues);
        return canonicalizationResult;
    }
}
