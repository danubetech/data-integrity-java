package com.danubetech.dataintegrity.verifier;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.secp256k1_ES256K_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.dataintegrity.canonicalizer.JCSCanonicalizer;
import com.danubetech.dataintegrity.suites.JcsEcdsaSecp256K1Signature2019DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import io.ipfs.multibase.Base58;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class JcsEcdsaSecp256k1Signature2019LdVerifier extends LdVerifier<JcsEcdsaSecp256K1Signature2019DataIntegritySuite> {

    public JcsEcdsaSecp256k1Signature2019LdVerifier(ByteVerifier verifier) {

        super(DataIntegritySuites.DATA_INTEGRITY_SUITE_JCSECDSASECP256L1SIGNATURE2019, verifier, new JCSCanonicalizer());
    }

    public JcsEcdsaSecp256k1Signature2019LdVerifier(ECKey publicKey) {

        this(new secp256k1_ES256K_PublicKeyVerifier(publicKey));
    }

    public JcsEcdsaSecp256k1Signature2019LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String signatureValue = (String) dataIntegrityProof.getJsonObject().get("signatureValue");
        if (signatureValue == null) throw new GeneralSecurityException("No 'signatureValue' in proof.");

        boolean verify;

        byte[] bytes = Base58.decode(signatureValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.ES256K);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof) throws GeneralSecurityException {

        return verify(signingInput, dataIntegrityProof, this.getVerifier());
    }
}
