package crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Security;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import java.security.Provider;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;

public abstract class ECDH_BC
{
	// ensures the DH agreement is between two parties
	private static final boolean LAST_PHASE = true;
    


	/**
	 * 
	 * Generates a keyPair for Elliptic Curve Diffie Hellman to be used to 
	 * for public/private key pairs
	 * 
	 * @return				KeyPair 
	 * @throws Exception
	 */
    public static KeyPair generateKeys() throws Exception
    {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
		kpgen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
        return kpgen.generateKeyPair();
    }




	/**
	 * 
	 * Used between two parties to allow participants have a shared secret
	 * 
	 * @param srcPri
	 * @param destPub
	 * @return
	 * @throws Exception
	 */
	public static SecretKey srcAgreement(PrivateKey srcPri, PublicKey destPub) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		ka.init(srcPri);
		ka.doPhase(destPub, LAST_PHASE);
		return ka.generateSecret("AES[256]");
	}

    public static byte[] savePubKey(PublicKey key) throws Exception
	{
		//return key.getEncoded();
		ECPublicKey eckey = (ECPublicKey)key;
		return eckey.getQ().getEncoded(true);
	}

	public static PublicKey loadPubKey(byte[] data) throws Exception
	{
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
		ECPublicKeySpec pubKey = new ECPublicKeySpec(
				params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(pubKey);
	}

	public static byte[] savePriKey(PrivateKey pri) throws Exception
	{
		//return key.getEncoded();
		ECPrivateKey eckey = (ECPrivateKey)pri;
		return eckey.getD().toByteArray();
	}

	public static PrivateKey loadPriKey(byte [] data) throws Exception
	{
		//KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		//return kf.generatePrivate(new PKCS8EncodedKeySpec(data));

		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePrivate(prvkey);
	}

    public static byte[] doECDH(byte[] dataPub, PrivateKey pri) throws Exception
	{
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		ka.init(pri);
		ka.doPhase(loadPubKey(dataPub), true);
		byte[] secret = ka.generateSecret();
        return secret;
		//System.out.println(name + bytesToHex(secret));
	}

	/* 
	
    public static void main(String[] args) throws Exception {
		// each party generates their own keyPair individually
		KeyPair aliceKeys = ECDH_BC.generateKeys(); 
		KeyPair bobKeys = ECDH_BC.generateKeys();
		PrivateKey alicePri = aliceKeys.getPrivate();
		PublicKey alicePub = aliceKeys.getPublic();
		PrivateKey bobPri = bobKeys.getPrivate();
		PublicKey bobPub = bobKeys.getPublic();

		SecretKey aliceSecret = srcAgreement(alicePri, bobPub); // bob shares pub key to alice
		SecretKey bobSecret = srcAgreement(bobPri, alicePub); // alice shares pub key to bob

		SecretKey bobEphem = new SecretKeySpec(Digest.HMAC256(bobSecret.getEncoded()), "HmacSHA256");
		SecretKey aliceEphem = new SecretKeySpec(Digest.HMAC256(aliceSecret.getEncoded()), "HmacSHA256");
		IvParameterSpec iv = Utils.generateIV();
		IvParameterSpec iv2 = Utils.generateIV();

		String cipher = AES.encrypt(aliceEphem, "hi bobby", iv);
		System.out.println(AES.decrypt(bobEphem, cipher, iv));
		System.out.println(AES.decrypt(aliceSecret, cipher, iv)); // intercepted secret results in nothing of interest
		System.out.println(AES.decrypt(bobEphem, cipher, iv2)); // incorrect iv does results in nothing of interest
	} */
}
