
package crypto;

import java.math.BigInteger;
import java.security.Provider;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import java.util.Random;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SealedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.BadPaddingException;
import java.io.*;


public abstract class AES {

    private static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";
    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final int SPOOF_LENGTH = 128;
    private static final int RANDOM_STR_LEN = 3;
    
    

    private static SecretKey createSpoofedKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(SPOOF_LENGTH);
        return kg.generateKey();
    }

    private static String getRandomString() {
        Random rand = new Random();
        String ret = "";
        for (int i = 0; i < RANDOM_STR_LEN; i++) {
            ret += (char)(rand.nextInt(26) + 'A');
        }
        return ret;
    }

    public static String EncryptFile(byte[] key, String fname, IvParameterSpec iv, int n) throws Exception{
        FileInputStream fis = new FileInputStream(fname);
        byte[] buffer = new byte[10];
        StringBuilder sb = new StringBuilder();
        while (fis.read(buffer) != -1) {
	        sb.append(new String(buffer));
	        buffer = new byte[10];
        }
        fis.close();
        String content = sb.toString();
        SecretKey enc = AES.setKey(key);
        String encdata = AES.encrypt(enc, content, iv);
        
        System.out.println("DATA[0] = " + encdata.charAt(0));
        System.out.println("CONTENT LEN = " + encdata.length());
        

        /* Create encrypted tmp file */
        File output = new File("output.txt");
        FileWriter writer = new FileWriter(output);
        writer.write(n + "\n" + encdata);
        writer.flush();
        writer.close();

        return "output.txt";
    }

    public static String DecryptFile(byte[] key, String fname, IvParameterSpec iv, int n) throws Exception{
        FileInputStream fis = new FileInputStream(fname);
        byte[] buffer = new byte[10];
        StringBuilder sb = new StringBuilder();
        while (fis.read(buffer) != -1) {
	        sb.append(new String(buffer));
	        buffer = new byte[10];
        }
        fis.close();
        String content = sb.toString();

        /* Get N from first line of string */
        int newLineIndex = content.indexOf("\n");
        String offset = content.substring(0, newLineIndex);
        String data = content.substring(newLineIndex + 1);

        //System.out.println("DATA[0] = " + data.charAt(0));
        //System.out.println("LEN = " + data.length());

        /* Create the new key */
        int to_hash = Integer.parseInt(offset) - n;
        System.out.println("TO HASH = " + to_hash);
        key = AES.hashKey(key, to_hash);
        SecretKey dec = AES.setKey(key);

        /* Delete the old file */
        File file = new File(fname);
        file.delete();

        /* Create new decrypted file */
        File output = new File(fname);
        FileWriter writer = new FileWriter(output);
        writer.write(AES.decrypt(dec, data.trim(), iv));
        writer.flush();
        writer.close();

        return fname;
    }

    public static SecretKey genKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(SPOOF_LENGTH);
        return kg.generateKey();
    }

    public static SecretKey setKey(byte[] key) throws GeneralSecurityException {
        return new SecretKeySpec(key, "AES");
    }

    public static byte[] getBytes(SecretKey key){
        return key.getEncoded();
    }

    public static byte[] hashKey(byte[] key, int n) throws Exception{

        byte[] rez = key;
        for(int i = 0; i < n; i++){
            rez = Utils.hash(rez);
        }

        return rez;
    }

    /**
     * 
     * @param key
     * @param plainText
     * @param iv            iv for encryption and decryption must be the same!
     * @return              encrypted message
     * @throws Exception
     */
    public static String encrypt(SecretKey key, String plainText, IvParameterSpec iv) throws Exception {
        byte[] textBytes = plainText.getBytes();
        Cipher aes = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        aes.init(Cipher.ENCRYPT_MODE, key, iv); //initializing the cipher.
        return Utils.encodeBytes(aes.doFinal(textBytes));

    }

    /**
     * 
     * @param key
     * @param cipherText
     * @param iv            iv for encryption and decryption must be the same!
     * @return              decrypted message
     * @throws Exception
     */
    public static String decrypt(SecretKey key, String cipherText, IvParameterSpec iv) throws Exception {
        try {
            Cipher aes = Cipher.getInstance(TRANSFORMATION, PROVIDER);
            aes.init(Cipher.DECRYPT_MODE, key, iv); //initializing the cipher.
            return new String (aes.doFinal(Base64.getDecoder().decode(cipherText)));
        } catch (BadPaddingException e) {
            // return hashed nonsense to avoid obfuscate exception handling 
            Random rand = new Random();
            return Utils.hash(encrypt(createSpoofedKey(), getRandomString(), iv)).toString();
        }
    }

    /**
     * 
     * @param key
     * @param plainText
     * @param iv            iv for encryption and decryption must be the same!
     * @return              encrypted message
     * @throws Exception
     */
    public static SealedObject encrypt(SecretKey key, Serializable plainObject, IvParameterSpec iv) throws Exception {
        Cipher aes = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        aes.init(Cipher.ENCRYPT_MODE, key, iv); //initializing the cipher.
        return new SealedObject(plainObject, aes);
    }

    /**
     * 
     * @param key
     * @param cipherText
     * @param iv            iv for encryption and decryption must be the same!
     * @return              decrypted message
     * @throws Exception
     */
    public static Object decrypt(SecretKey key, SealedObject encryptedObject, IvParameterSpec iv) throws Exception {
        try {
            Cipher aes = Cipher.getInstance(TRANSFORMATION, PROVIDER);
            aes.init(Cipher.DECRYPT_MODE, key, iv); //initializing the cipher.
            return encryptedObject.getObject(aes);
        } catch (BadPaddingException e) {
            // to avoid letting the user know there was bad padding
            return null;
        }
    }
}
