package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.PublicKeyBytes;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class DidBtc1PatchTest {

    @Test
    public void testPatch1() throws JsonLDException, GeneralSecurityException, IOException {

        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.1.jsonld"))));
        jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

        JsonLDObject verificationMethod = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.verification-method.1.jsonld"))));
        String publicKeyMultibase = (String) verificationMethod.getJsonObject().get("publicKeyMultibase");
        byte[] publicKeyBytes = Arrays.copyOfRange(Multibase.decode(publicKeyMultibase), 2, 35);
        ECKey publicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);

        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, publicKey);
        DataIntegrityProofLdVerifier verifier = new DataIntegrityProofLdVerifier(publicKeyVerifier);
        boolean verify = verifier.verify(jsonLdObject);

        assertTrue(verify);
    }

    @Test
    public void testPatch2() throws JsonLDException, GeneralSecurityException, IOException {

        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.2.jsonld"))));
        jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

        JsonLDObject verificationMethod = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.verification-method.2.jsonld"))));
        String publicKeyMultibase = (String) verificationMethod.getJsonObject().get("publicKeyMultibase");
        byte[] publicKeyBytes = Arrays.copyOfRange(Multibase.decode(publicKeyMultibase), 2, 35);
        ECKey publicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);

        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, publicKey);
        DataIntegrityProofLdVerifier verifier = new DataIntegrityProofLdVerifier(publicKeyVerifier);
        boolean verify = verifier.verify(jsonLdObject);

        assertTrue(verify);
    }

    @Test
    public void testPatch3() throws JsonLDException, GeneralSecurityException, IOException {

        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.3.jsonld"))));
        jsonLdObject.setDocumentLoader(DataIntegrityContexts.DOCUMENT_LOADER);

        JsonLDObject verificationMethod = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(DidBtc1PatchTest.class.getResourceAsStream("did-btc1-patch.verification-method.3.jsonld"))));
        String publicKeyMultibase = (String) verificationMethod.getJsonObject().get("publicKeyMultibase");
        byte[] publicKeyBytes = Arrays.copyOfRange(Multibase.decode(publicKeyMultibase), 2, 35);
        ECKey publicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);

        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, publicKey);
        DataIntegrityProofLdVerifier verifier = new DataIntegrityProofLdVerifier(publicKeyVerifier);
        boolean verify = verifier.verify(jsonLdObject);

        assertTrue(verify);
    }
}
