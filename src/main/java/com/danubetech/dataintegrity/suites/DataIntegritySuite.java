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
	private final Map<KeyTypeName, List<String>> jwsAlgorithmsByKeyTypeName;
	private final List<URI> supportedJsonLDContexts;

	public DataIntegritySuite(String term, URI id, Map<KeyTypeName, List<String>> jwsAlgorithmsByKeyTypeName, List<URI> supportedJsonLDContexts) {
		this.term = term;
		this.id = id;
		this.type = URI_TYPE_SIGNATURESUITE;
		this.jwsAlgorithmsByKeyTypeName = jwsAlgorithmsByKeyTypeName;
		this.supportedJsonLDContexts = supportedJsonLDContexts;
	}

	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName) {
		return this.getJwsAlgorithmsByKeyTypeName().get(keyTypeName);
	}

	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName, String cryptosuite) {
		return this.findJwsAlgorithmsForKeyTypeName(keyTypeName);
	}

	public String findDefaultJwsAlgorithmForKeyTypeName(KeyTypeName keyTypeName) {
		List<String> foundAlgorithmsForKeyTypeName = this.findJwsAlgorithmsForKeyTypeName(keyTypeName);
		return (foundAlgorithmsForKeyTypeName == null || foundAlgorithmsForKeyTypeName.isEmpty()) ? null : foundAlgorithmsForKeyTypeName.get(0);
	}

	public String findDefaultJwsAlgorithmForKeyTypeName(KeyTypeName keyTypeName, String cryptosuite) {
		List<String> foundAlgorithmsForKeyTypeName = this.findJwsAlgorithmsForKeyTypeName(keyTypeName, cryptosuite);
		return (foundAlgorithmsForKeyTypeName == null || foundAlgorithmsForKeyTypeName.isEmpty()) ? null : foundAlgorithmsForKeyTypeName.get(0);
	}

	public URI getDefaultSupportedJsonLDContext() {
		List<URI> supportedJsonLDContexts = this.getSupportedJsonLDContexts();
		return (supportedJsonLDContexts == null || supportedJsonLDContexts.isEmpty()) ? null : supportedJsonLDContexts.get(0);
	}

	public String getTerm() {
		return this.term;
	}

	public URI getId() {
		return this.id;
	}

	public URI getType() {
		return this.type;
	}

	public Map<KeyTypeName, List<String>> getJwsAlgorithmsByKeyTypeName() {
		return this.jwsAlgorithmsByKeyTypeName;
	}

	public List<URI> getSupportedJsonLDContexts() {
		return this.supportedJsonLDContexts;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || getClass() != o.getClass()) return false;
		DataIntegritySuite that = (DataIntegritySuite) o;
		return Objects.equals(term, that.term) && Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(jwsAlgorithmsByKeyTypeName, that.jwsAlgorithmsByKeyTypeName) && Objects.equals(supportedJsonLDContexts, that.supportedJsonLDContexts);
	}

	@Override
	public int hashCode() {
		return Objects.hash(term, id, type, jwsAlgorithmsByKeyTypeName, supportedJsonLDContexts);
	}

	@Override
	public String toString() {
		return "DataIntegritySuite{" +
				"term='" + term + '\'' +
				", id=" + id +
				", type=" + type +
				", keyTypeNamesAndJwsAlgorithms=" + jwsAlgorithmsByKeyTypeName +
				", supportedJsonLDContexts=" + supportedJsonLDContexts +
				'}';
	}
}
