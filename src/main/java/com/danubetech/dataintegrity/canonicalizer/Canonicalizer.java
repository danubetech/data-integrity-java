package com.danubetech.dataintegrity.canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;

public abstract class Canonicalizer {

    private final List<String> algorithms;

    public abstract String canonicalize(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException;
    public abstract byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException;

    public Canonicalizer(List<String> algorithms) {
        this.algorithms = algorithms;
    }

    public List<String> getAlgorithms() {
        return algorithms;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Canonicalizer that = (Canonicalizer) o;
        return Objects.equals(algorithms, that.algorithms);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithms);
    }

    @Override
    public String toString() {
        return "Canonicalizer{" +
                "algorithms='" + algorithms + '\'' +
                '}';
    }
}
