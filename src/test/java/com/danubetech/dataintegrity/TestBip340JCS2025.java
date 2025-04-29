package com.danubetech.dataintegrity;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.signer.DataIntegrityProofLdSigner;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.PrivateKeyBytes;
import com.danubetech.keyformats.PublicKeyBytes;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.crypto.ECKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestBip340JCS2025 {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testSign() throws JsonLDException, GeneralSecurityException, IOException {

        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(TestBip340JCS2025.class.getResourceAsStream("bip340-jcs-2025.unsigned.json"))));
        jsonLdObject.setDocumentLoader(DOCUMENT_LOADER);

        Map<String, Object> keypair = objectMapper.readValue(new InputStreamReader(Objects.requireNonNull(TestBip340JCS2025.class.getResourceAsStream("bip340-jcs-2025.keypair.json"))), Map.class);

        byte[] privateKeyMultibase = Multibase.decode((String) keypair.get("privateKeyMultibase"));
        byte[] privateKeyBytes = Arrays.copyOfRange(privateKeyMultibase, 2, 34);
        ECKey privateKey = PrivateKeyBytes.bytes_to_secp256k1PrivateKey(privateKeyBytes);

        byte[] publicKeyMultibase = Multibase.decode((String) keypair.get("publicKeyMultibase"));
        byte[] publicKeyBytes = Arrays.copyOfRange(publicKeyMultibase, 2, 35);
        ECKey publicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);

        PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, privateKey);
        DataIntegrityProofLdSigner signer = new DataIntegrityProofLdSigner(privateKeySigner);
        signer.setCryptosuite("bip340-jcs-2025");
        signer.sign(jsonLdObject);

        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, publicKey);
        DataIntegrityProofLdVerifier verifier = new DataIntegrityProofLdVerifier(publicKeyVerifier);
        boolean verify = verifier.verify(jsonLdObject);

        assertTrue(verify);
    }

    @Test
    public void testVerify() throws JsonLDException, GeneralSecurityException, IOException {

        JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(TestBip340JCS2025.class.getResourceAsStream("bip340-jcs-2025.signed.json"))));
        jsonLdObject.setDocumentLoader(DOCUMENT_LOADER);

        Map<String, Object> keypair = objectMapper.readValue(new InputStreamReader(Objects.requireNonNull(TestBip340JCS2025.class.getResourceAsStream("bip340-jcs-2025.keypair.json"))), Map.class);

        byte[] publicKeyMultibase = Multibase.decode((String) keypair.get("publicKeyMultibase"));
        byte[] publicKeyBytes = Arrays.copyOfRange(publicKeyMultibase, 2, 35);
        ECKey publicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes);

        PublicKeyVerifier<?> publicKeyVerifier = PublicKeyVerifierFactory.publicKeyVerifierForKey(KeyTypeName.secp256k1, JWSAlgorithm.ES256KS, publicKey);
        DataIntegrityProofLdVerifier verifier = new DataIntegrityProofLdVerifier(publicKeyVerifier);
        boolean verify = verifier.verify(jsonLdObject);

        assertTrue(verify);
    }

    public static final DocumentLoader DOCUMENT_LOADER;

    static {
        Map<URI, JsonDocument> CONTEXTS;
        try {
            CONTEXTS = new HashMap<>(DataIntegrityContexts.CONTEXTS);
            CONTEXTS.put(URI.create("https://www.w3.org/ns/credentials/examples/v2"),
                    JsonDocument.of(MediaType.JSON_LD, new StringReader(
                            """
                            {
                              "@context": {
                                "@vocab": "https://www.w3.org/ns/credentials/examples#"
                              }
                            }
                            """
                    )));
            for (Map.Entry<URI, JsonDocument> context : CONTEXTS.entrySet()) {
                context.getValue().setDocumentUrl(context.getKey());
            }
        } catch (JsonLdError ex) {
            throw new ExceptionInInitializerError(ex);
        }
        DOCUMENT_LOADER = new ConfigurableDocumentLoader(CONTEXTS);
    }
}
