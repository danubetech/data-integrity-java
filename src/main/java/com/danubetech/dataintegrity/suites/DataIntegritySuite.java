package com.danubetech.dataintegrity.suites;

import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public abstract class DataIntegritySuite {

	public static final URI URI_TYPE_SIGNATURESUITE = URI.create("https://w3id.org/security#SignatureSuite");

	private final String term;
	private final URI id;
	private final URI type;
	private final Map<KeyTypeName, List<String>> keyTypeNamesAndJwsAlgorithms;
	private final List<URI> supportedJsonLDContexts;

	public DataIntegritySuite(String term, URI id, Map<KeyTypeName, List<String>> keyTypeNamesAndJwsAlgorithms, List<URI> supportedJsonLDContexts) {
		this.term = term;
		this.id = id;
		this.type = URI_TYPE_SIGNATURESUITE;
		this.keyTypeNamesAndJwsAlgorithms = keyTypeNamesAndJwsAlgorithms;
		this.supportedJsonLDContexts = supportedJsonLDContexts;
	}

	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName) {
		return this.getKeyTypeNamesAndJwsAlgorithms().get(keyTypeName);
	}

	public String findDefaultJwsAlgorithmForKeyTypeName(KeyTypeName keyTypeName) {
		List<String> foundAlgorithmsForKeyTypeName = this.findJwsAlgorithmsForKeyTypeName(keyTypeName);
		return (foundAlgorithmsForKeyTypeName == null || foundAlgorithmsForKeyTypeName.isEmpty()) ? null : foundAlgorithmsForKeyTypeName.get(0);
	}

	public URI getDefaultSupportedJsonLDContext() {
		List<URI> supportedJsonLDContexts = this.getSupportedJsonLDContexts();
		return (supportedJsonLDContexts == null || supportedJsonLDContexts.isEmpty()) ? null : supportedJsonLDContexts.get(0);
	}

	public String getTerm() {
		return term;
	}

	public URI getId() {
		return id;
	}

	public URI getType() {
		return type;
	}

	public Map<KeyTypeName, List<String>> getKeyTypeNamesAndJwsAlgorithms() {
		return keyTypeNamesAndJwsAlgorithms;
	}

	public List<URI> getSupportedJsonLDContexts() {
		return supportedJsonLDContexts;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		DataIntegritySuite that = (DataIntegritySuite) o;
		return Objects.equals(term, that.term) && Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(keyTypeNamesAndJwsAlgorithms, that.keyTypeNamesAndJwsAlgorithms) && Objects.equals(supportedJsonLDContexts, that.supportedJsonLDContexts);
	}

	@Override
	public int hashCode() {
		return Objects.hash(term, id, type, keyTypeNamesAndJwsAlgorithms, supportedJsonLDContexts);
	}

	@Override
	public String toString() {
		return "DataIntegritySuite{" +
				"term='" + term + '\'' +
				", id=" + id +
				", type=" + type +
				", keyTypeNamesAndJwsAlgorithms=" + keyTypeNamesAndJwsAlgorithms +
				", supportedJsonLDContexts=" + supportedJsonLDContexts +
				'}';
	}
}
