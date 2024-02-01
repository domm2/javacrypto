package crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.security.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import javax.crypto.SecretKey;

public class Utils {
    
    private final static char[] HEXARRAY = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEXARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEXARRAY[v & 0x0F];
		}
		return new String(hexChars);
	}

    public static byte[] hash(String text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Change this to UTF-16 if needed
        md.update(text.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        return digest;
        //String hex = String.format("%064x", new BigInteger(1, digest));
        //System.out.println(hex);
    }
    public static byte[] hash(byte[] text) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(text);
        byte[] digest = md.digest();
        return digest;
    }
    

    public static boolean verify_hash(String hash, byte[] to_compute) {
        if (to_compute == null) return false;
        String computed = bytesToHex(to_compute);
        return hash.equals(computed);
    }
    
    /**
     * 
     * Generates an IV to be used for AES encryption/decryption between
     * two parties. Each party must use the same IV.
     * 
     * @return
     */
    public static IvParameterSpec generateIV() {
        SecureRandom secran = new SecureRandom();
        byte[] IV = new byte[16];
        secran.nextBytes(IV);
        return new IvParameterSpec(IV);
    }

    /**
    * Combines two byte arrays
    */
    public static byte[] concatenate_bytes(byte[] arr0, byte[] arr1) throws Exception {
        if (arr0 == null || arr1 == null) return null;
        ByteArrayOutputStream temp = new ByteArrayOutputStream();
        temp.write(arr0);
        temp.write(arr1);
        return temp.toByteArray();
    }

    /**
     * Returns the String encoding of a SecretKey
     */
    public static String secret_key_to_string(SecretKey key) throws Exception {
        return encodeBytes(key.getEncoded());
    }



    /**
     * Returns if a String matches the given regex pattern
     */
    public static boolean matches_pattern(String pattern, String str) {
        return java.util.regex.Pattern.matches(pattern, str);
    }

    
    /**
     * 
     * Encodes bytes. Utilized for AES encryption to avoid 
     * last block incomplete errors 
     * 
     * @param bytes
     * @return
     */
    public static String encodeBytes(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 
     * Decodes encoded bytes. Utilized for AES encryption to avoid 
     * last block incomplete errors 
     * 
     * @param bytes
     * @return
     */
    public static byte[] decodeBytes(byte[] bytes) {
        return Base64.getDecoder().decode(bytes);
    }

    public static boolean saveByteArr(byte[] arr, String fname){
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream(fname));
            outStream.writeObject(arr);
            return true;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public static byte[] loadByteArr(String fname){
        ObjectInputStream userStream;
        try {
            FileInputStream fis = new FileInputStream(fname);
            userStream = new ObjectInputStream(fis);
            byte[] key = (byte[]) userStream.readObject();
            return key;
            
        } catch(FileNotFoundException e) {
            System.out.println("KEY not found. Failed to load file.");
        } catch(IOException e) {
            System.out.println("Error reading from key file");
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from key file");
        }

        return null;
    }

    public static byte[] genChall(){
        SecureRandom secran = new SecureRandom();
        byte[] ch = new byte[16];
        secran.nextBytes(ch);
        return ch;
    }
}
