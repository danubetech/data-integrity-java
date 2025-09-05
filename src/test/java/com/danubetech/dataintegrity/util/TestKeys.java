package com.danubetech.dataintegrity.util;

import com.danubetech.keyformats.PrivateKeyBytes;
import com.danubetech.keyformats.PublicKeyBytes;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.base.Base58;
import org.bitcoinj.crypto.ECKey;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TestKeys {

	public static final String testEd25519PrivateKeyString =
			"BFVcBZTsRtYK5zNMC2DsDVv7hJCFnfE48SKdhScWiX9q";

	public static final String testEd25519PublicKeyString =
			"FyfKP2HvTKqDZQzvyL38yXH7bExmwofxHf2NR5BrcGf1";

	public static final String testSecp256k1PrivateKeyString =
			"2ff4e6b73bc4c4c185c68b2c378f6b233978a88d3c8ed03df536f707f084e24e";

	public static final String testSecp256k1PublicKeyString =
			"0343f9455cd248e24c262b1341bbe37cea360e1c5ce526e5d1a71373ba6e557018";

	public static final String testP256PrivateKeyString =
			"76e19702f6cfcdf01ca1e2ea9578df91f5770eab0e76ce6a8bebb08d5d670fe0";

	public static final String testP256PublicKeyString =
			"0334d2aae49413879d66e2819128b6645f0e379fcf9cda9c29b4eaeb6d44b082d6";

	public static final String testP384PrivateKeyString =
			"37354f4d1b6bd8ce37f0a934d566431b17379834aaee1223d8c0b0e49206432d333768f90dc64ed305c83eee091c6fd5";

	public static final String testP384PublicKeyString =
			"02322d3be93a752fab4762659da7ac26b8d5c0da2c148211f33549f3cd4d983a56a84fc59ba72df21f37098d99500f3ef1";

	public static final String testRSAPrivateKeyString =
					"""
					-----BEGIN PRIVATE KEY-----
					MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2lLVmZ9UpU/kq
					h8iEwE/S1JZziqWHp+baWtlKS4rFSMRpaPNlLOzvaAQgbGtpa6wx2hG5XnjGxZHJ
					/kp5lPRL4jk+uV7ch2LeAgKI7g3C8yTonBIFwlbCZIsUQrJRKcHYK1+IZzT/mtAK
					lwS38OfmIz4E2ft+qmgshuSzytcpQiPz6oxWqRNewQp4qKcTbe3XKQyV2w1po4f6
					G8a2Lkm3YMycfUmOhd0Nd/G9I//SCNRhvR6S251gVegDrB6SZDIl4ia+DHgzLPUj
					iIe2Rj8KnsngyfV6Nnoc2bK+hMT/g65jW4J5i/hTJcVzWzW5TJi2PjPnuqwcaxLh
					1DcDYwmzAgMBAAECggEAKp0KuZwCZGL1BLgsVM+N0edMNitl9wN5Hf2WOYDoIqOZ
					NAEKzdJuenIMhITJjRFUX05GVL138uyp2js/pqDdY9ipA7rAKThwGuDdNphZHech
					9ih3DGEPXs+YpmHqvIbCd3GoGm38MKwxYkddEpFnjo8rKna1/BpJthrFxjDRhw9D
					xJBycOdH2yWTyp62ZENPvneK40H2a57W4QScTgfecZqD59m2fGUaWaX5uUmIxaEm
					tGoJnd9RE4oywKhgN7/TK7wXRlqA4UoRPiH2ACrdU+/cLQL9Jc0u0GqZJK31LDbO
					eN95QgtSCc72k3Vtzy3CrVpp5TAA67s1Gj9Skn+CAQKBgQDkEZTVztp//mwXJ+xr
					6icgmCjkFm7y4e/PdTJvw4DRr4b1Q87VKEtiNfTBR+FlwUHt/A+2CaZgA3rAoZVx
					714wBtfg+WI+Tev4Fylm48qS4uT/AW+BYBDkerDaIS7BctXT97xzaBpS3+HIwLn6
					cVzi/QGa/o1Po9+vL5SsrcEpZwKBgQDM8P4H6eueDAX4730Ee9vjtcYpHs43wkIj
					onFq/MiS6wxcIHyszJhbzMuzrwvwksDNZnfigyrQU9SfKwHFzmdMXw1vgFnFNnn7
					1wd+gqthMjdhayZVbYWkIkUSMyzg1dnbw8GRL1vjON9LYqE12SYJ45hTS0mk1/CY
					5Mj3Sp5R1QKBgGia88P5I1ivbg5U3mhEtnuJrr+m1m6KWH6zx1VhuzTxqBnYZwZ3
					e9Po4YDBIk2UjVPFV8Nru6awEd5GfpAKdQ3cJannWDsxbDiXDwNFGYWzkcqwct9J
					G5Zf+7ugmpxZul+FcicQqXo3e4yjcOnAkxT9bH4VoOTVSeRFE5D8BOujAoGASwz1
					+m/vmTFN/pu1bK7vF7S5nNVrL4A0OFiEsGliCmuJWzOKdL14DiYxctvnw3H6qT2d
					KZZfV2tbse5N9+JecdldUjfuqAoLIe7dD7dKi42YOlTC9QXmqvTh1ohnJu8pmRFX
					EZQGUm/BVhoIb2/WPkjav6YSkguCUHt4HRd2YwECgYAGhy4I4Q6r6jIsMAvDMxdT
					yA5/cgvVDX8FbCx2gA2iHqLXv2mzGATgldOhZyldlBCq5vyeDATq5H1+l3ebo388
					vhPnm9sMPKM8qasva20LaA63H0quk+H5nstBGjgETjycckmvKy0od8WVofYbsnEc
					2AwFhUAPK203T2oShq/w6w==
					-----END PRIVATE KEY-----
					""";

	public static final String testRSAPublicKeyString =
					"""
					-----BEGIN PUBLIC KEY-----
					MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtpS1ZmfVKVP5KofIhMBP
					0tSWc4qlh6fm2lrZSkuKxUjEaWjzZSzs72gEIGxraWusMdoRuV54xsWRyf5KeZT0
					S+I5Prle3Idi3gICiO4NwvMk6JwSBcJWwmSLFEKyUSnB2CtfiGc0/5rQCpcEt/Dn
					5iM+BNn7fqpoLIbks8rXKUIj8+qMVqkTXsEKeKinE23t1ykMldsNaaOH+hvGti5J
					t2DMnH1JjoXdDXfxvSP/0gjUYb0ektudYFXoA6wekmQyJeImvgx4Myz1I4iHtkY/
					Cp7J4Mn1ejZ6HNmyvoTE/4OuY1uCeYv4UyXFc1s1uUyYtj4z57qsHGsS4dQ3A2MJ
					swIDAQAB
					-----END PUBLIC KEY-----
					""";

	public static final byte[] testEd25519PrivateKey;
	public static final byte[] testEd25519PublicKey;
	public static final ECKey testSecp256k1PrivateKey;
	public static final ECKey testSecp256k1PublicKey;
	public static final ECPrivateKey testP256PrivateKey;
	public static final ECPublicKey testP256PublicKey;
	public static final ECPrivateKey testP384PrivateKey;
	public static final ECPublicKey testP384PublicKey;
	public static final KeyPair testRSAPrivateKey;
	public static final RSAPublicKey testRSAPublicKey;

	static {

		try {

			testEd25519PrivateKey = PrivateKeyBytes.bytes_to_Ed25519PrivateKey(Base58.decode(testEd25519PrivateKeyString));
			testEd25519PublicKey = PublicKeyBytes.bytes_to_Ed25519PublicKey(Base58.decode(testEd25519PublicKeyString));

			testSecp256k1PrivateKey = PrivateKeyBytes.bytes_to_secp256k1PrivateKey(Hex.decodeHex(testSecp256k1PrivateKeyString));
			testSecp256k1PublicKey = PublicKeyBytes.bytes_to_secp256k1PublicKey(Hex.decodeHex(testSecp256k1PublicKeyString));

			testP256PrivateKey = PrivateKeyBytes.bytes_to_P_256PrivateKey(Hex.decodeHex(testP256PrivateKeyString));
			testP256PublicKey = PublicKeyBytes.bytes_to_P_256PublicKey(Hex.decodeHex(testP256PublicKeyString));

			testP384PrivateKey = PrivateKeyBytes.bytes_to_P_384PrivateKey(Hex.decodeHex(testP384PrivateKeyString));
			testP384PublicKey = PublicKeyBytes.bytes_to_P_384PublicKey(Hex.decodeHex(testP384PublicKeyString));

			String testRSAPublicKeyPEM = testRSAPublicKeyString;
			testRSAPublicKeyPEM = testRSAPublicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "").replace("\n", "");
			testRSAPublicKeyPEM = testRSAPublicKeyPEM.replace("-----END PUBLIC KEY-----", "");
			byte[] testRSAPublicKeyEncoded = Base64.decodeBase64(testRSAPublicKeyPEM);
			X509EncodedKeySpec testRSAPublicKeySpec = new X509EncodedKeySpec(testRSAPublicKeyEncoded);
			KeyFactory testRSAPublicKeyKeyFactory = KeyFactory.getInstance("RSA");
			testRSAPublicKey = (RSAPublicKey) testRSAPublicKeyKeyFactory.generatePublic(testRSAPublicKeySpec);

			String testRSAPrivateKeyPEM = testRSAPrivateKeyString;
			testRSAPrivateKeyPEM = testRSAPrivateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "").replace("\n", "");
			testRSAPrivateKeyPEM = testRSAPrivateKeyPEM.replace("-----END PRIVATE KEY-----", "");
			byte[] testRSAPrivateKeyEncoded = Base64.decodeBase64(testRSAPrivateKeyPEM);
			PKCS8EncodedKeySpec testRSAPrivateKeySpec = new PKCS8EncodedKeySpec(testRSAPrivateKeyEncoded);
			KeyFactory testRSAPrivateKeyKeyFactory = KeyFactory.getInstance("RSA");
			testRSAPrivateKey = new KeyPair(testRSAPublicKey, testRSAPrivateKeyKeyFactory.generatePrivate(testRSAPrivateKeySpec));
		} catch (Exception ex) {

			throw new RuntimeException(ex.getMessage(), ex);
		}
	}
}
