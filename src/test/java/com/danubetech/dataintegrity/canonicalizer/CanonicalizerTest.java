package com.danubetech.dataintegrity.canonicalizer;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.util.TestUtil;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CanonicalizerTest {

	static final Map<URI, JsonDocument> localCache;
	static final DocumentLoader documentLoader;

	static {

		localCache = new HashMap<>();

		try {

			JsonDocument jsonDocument1 = JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("security-v1.jsonld")));
			jsonDocument1.setDocumentUrl(URI.create("https://w3id.org/security/v1"));

			JsonDocument jsonDocument2 = JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("security-v2.jsonld")));
			jsonDocument2.setDocumentUrl(URI.create("https://w3id.org/security/v2"));

			JsonDocument jsonDocument3 = JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("security-v3-unstable.jsonld")));
			jsonDocument3.setDocumentUrl(URI.create("https://w3id.org/security/v3"));

			JsonDocument jsonDocument4 = JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("credentials-v1.jsonld")));
			jsonDocument4.setDocumentUrl(URI.create("https://www.w3.org/2018/credentials/v1"));

			JsonDocument jsonDocument5 = JsonDocument.of(MediaType.JSON_LD, Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("credentials-v2-unstable.jsonld")));
			jsonDocument5.setDocumentUrl(URI.create("https://www.w3.org/2018/credentials/v2"));

			localCache.put(jsonDocument1.getDocumentUrl(), jsonDocument1);
			localCache.put(jsonDocument2.getDocumentUrl(), jsonDocument2);
			localCache.put(jsonDocument3.getDocumentUrl(), jsonDocument3);
			localCache.put(jsonDocument4.getDocumentUrl(), jsonDocument4);
			localCache.put(jsonDocument5.getDocumentUrl(), jsonDocument5);
		} catch (JsonLdError ex) {

			throw new ExceptionInInitializerError(ex);
		}

		documentLoader = new ConfigurableDocumentLoader(localCache);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testNormalizationInput() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(documentLoader);
		String normalizedDocument = TestUtil.read(CanonicalizerTest.class.getResourceAsStream("input.normalized"));

		assertEquals(normalizedDocument, URDNA2015SHA256Canonicalizer.getInstance().canonicalize(jsonLdObject));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testNormalizationSigned() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("signed.good.rsa.jsonld"))));
		jsonLdObject.setDocumentLoader(documentLoader);
		String normalizedDocument = TestUtil.read(CanonicalizerTest.class.getResourceAsStream("signed.good.rsa.normalized"));

		assertEquals(normalizedDocument, URDNA2015SHA256Canonicalizer.getInstance().canonicalize(jsonLdObject));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testNormalizationVerifiableCredential() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("input.vc.jsonld"))));
		jsonLdObject.setDocumentLoader(documentLoader);
		String normalizedDocument = TestUtil.read(CanonicalizerTest.class.getResourceAsStream("input.vc.normalized"));

		assertEquals(normalizedDocument, URDNA2015SHA256Canonicalizer.getInstance().canonicalize(jsonLdObject));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testNormalizationVerifiablePresentation() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(CanonicalizerTest.class.getResourceAsStream("input.vp.jsonld"))));
		jsonLdObject.setDocumentLoader(documentLoader);
		String normalizedDocument = TestUtil.read(CanonicalizerTest.class.getResourceAsStream("input.vp.normalized"));

		assertEquals(normalizedDocument, URDNA2015SHA256Canonicalizer.getInstance().canonicalize(jsonLdObject));
	}
}
