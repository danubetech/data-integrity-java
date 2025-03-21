package com.danubetech.dataintegrity.jsonld;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import foundation.identity.jsonld.ConfigurableDocumentLoader;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class DataIntegrityContexts {

    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V1 = URI.create("https://w3id.org/security/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V2 = URI.create("https://w3id.org/security/v2");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_V3 = URI.create("https://w3id.org/security/v3");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1 = URI.create("https://w3id.org/security/bbs/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_SUITES_SECP256K1_2019_V1 = URI.create("https://w3id.org/security/suites/secp256k1-2019/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2018_V1 = URI.create("https://w3id.org/security/suites/ed25519-2018/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2020_V1 = URI.create("https://w3id.org/security/suites/ed25519-2020/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_SUITES_X25519_2019_V1 = URI.create("https://w3id.org/security/suites/x25519-2019/v1");
    public static final URI JSONLD_CONTEXT_W3ID_SECURITY_SUITES_JWS_2020_V1 = URI.create("https://w3id.org/security/suites/jws-2020/v1");
    public static final URI JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V1 = URI.create("https://w3id.org/data-integrity/v1");
    public static final URI JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2 = URI.create("https://w3id.org/data-integrity/v2");
    public static final URI JSONLD_CONTEXT_W3C_2018_CREDENTIALS_V1 = URI.create("https://www.w3.org/2018/credentials/v1");
    public static final URI JSONLD_CONTEXT_W3C_CREDENTIALS_V2 = URI.create("https://www.w3.org/ns/credentials/v2");

    public static final Map<URI, JsonDocument> CONTEXTS;
    public static final DocumentLoader DOCUMENT_LOADER;

    static {

        try {

            CONTEXTS = new HashMap<>();

            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-v2.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_V3,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-v3-unstable.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-bbs-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_SUITES_SECP256K1_2019_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-suites-secp256k1-2019.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2018_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-suites-ed25519-2018.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_SUITES_ED25519_2020_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-suites-ed25519-2020.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_SUITES_X25519_2019_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-suites-x25519-2019.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SECURITY_SUITES_JWS_2020_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("security-suites-jws-2020.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("dataintegrity-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_DATAINTEGRITY_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("dataintegrity-v2.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3C_2018_CREDENTIALS_V1,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("credentials-v1.jsonld"))));
            CONTEXTS.put(JSONLD_CONTEXT_W3C_CREDENTIALS_V2,
                    JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(DataIntegrityContexts.class.getResourceAsStream("credentials-v2.jsonld"))));

            for (Map.Entry<URI, JsonDocument> context : CONTEXTS.entrySet()) {
                context.getValue().setDocumentUrl(context.getKey());
            }
        } catch (JsonLdError ex) {

            throw new ExceptionInInitializerError(ex);
        }

        DOCUMENT_LOADER = new ConfigurableDocumentLoader(CONTEXTS);
    }
}
