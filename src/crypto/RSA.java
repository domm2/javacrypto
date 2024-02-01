package crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.*;


public class RSA {

    private Provider p;
    private KeyPairGenerator keyGen;
    private KeyPair rsaKeys;
    private Cipher rsaEnc;
    private Cipher rsaDec; 

    public RSA() throws GeneralSecurityException {
        p = new BouncyCastleProvider(); 
    }
    
    public void generateKeys() throws GeneralSecurityException {
        /* Generate 2048 RSA key */
        keyGen = KeyPairGenerator.getInstance("RSA", p);
        keyGen.initialize(2048);
        rsaKeys = keyGen.generateKeyPair();
    }

    public byte[] encrypt(byte[] msg) throws GeneralSecurityException {
        rsaEnc = Cipher.getInstance("RSA", p);
        rsaEnc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
        
        /* Convert msg to bytes for aencryption */
        byte[] c = rsaEnc.doFinal(msg);
        String cText = new String(c);
    
        return c;
    }

    public static byte[] encryptWithKey(PublicKey pub, byte[] msg) throws GeneralSecurityException {
        Provider p = new BouncyCastleProvider();
        Cipher rsaEnc = Cipher.getInstance("RSA", p);
        rsaEnc.init(Cipher.ENCRYPT_MODE, pub);
        
        /* Convert msg to bytes for aencryption */
        byte[] c = rsaEnc.doFinal(msg);
        String cText = new String(c);
    
        return c;
    }

    public byte[] decrypt(byte[] c) throws GeneralSecurityException{
        rsaDec = Cipher.getInstance("RSA", p);
        rsaDec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
        
        return rsaDec.doFinal(c);
    }
    
    public static byte[] decryptWithKey(PrivateKey pub, byte[] msg) throws GeneralSecurityException {
        Provider p = new BouncyCastleProvider();
        Cipher rsaDec = Cipher.getInstance("RSA", p);
        rsaDec.init(Cipher.DECRYPT_MODE, pub);
        
        /* Convert msg to bytes for aencryption */
        byte[] c = rsaDec.doFinal(msg);
    
        return c;
    }
	
    public byte[] savePubKey() throws Exception{
		//return key.getEncoded();
		return this.rsaKeys.getPublic().getEncoded();
	}
    
    public byte[] savePriKey() throws Exception{
		//return key.getEncoded();
		return this.rsaKeys.getPrivate().getEncoded();
	}

    public static PublicKey loadPubKey(byte[] keyBytes) throws RuntimeException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static PrivateKey loadPriKey(byte[] keyBytes) throws RuntimeException {
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /*private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }*/

    /*public static void main(String[] args) throws GeneralSecurityException{
        RSA rsa = new RSA();
        rsa.generateKeys();
       
        System.out.println("I WORK!");
        
        byte[] enc = rsa.encrypt( new String("Hello World").getBytes());
        try{
            byte[] key = rsa.savePriKey();

            byte[] decryptedMessage = decryptWithKey(loadPriKey(key), enc);
        
            //System.out.println("Encrypted:\n"+encryptedMessage);
            System.out.println("Decrypted:\n"+ new String(decryptedMessage));
        }catch(Exception e){
            e.printStackTrace();
        }
    }*/
}
