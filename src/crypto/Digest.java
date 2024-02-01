package crypto;


import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public abstract class Digest {
    protected static final String ENCODING = "UTF-8";

    
    /**
     * 
     * Returns a hashed value given the varargs
     * 
     * @param varargs
     * @param varargs[0]    key 
     * @param varargs[1]    data data to hash, if data is given
     * @return 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * 
     */
    public static byte[] HMAC256(byte[] key, String... vararg) 
            throws NoSuchAlgorithmException, InvalidKeyException {
        
        String algo = "HmacSHA256";
        SecretKeySpec sks = new SecretKeySpec(key, algo);
        Mac digest = Mac.getInstance(algo);
        digest.init(sks);
        if (vararg.length == 1) return digest.doFinal(vararg[0].getBytes());
        return digest.doFinal();
    }

    /**
     * 
     * Verifies if the given hashed hexExpected matches the hashed varargs
     * 
     * @param varargs
     * @param varargs[0]    key 
     * @param varargs[1]    data data to hash, if data is given
     * @return 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static boolean verifyHMAC256(byte[] expectedKeyInBytes, byte[] givenKey, String ... vararg) throws Exception {
        return expectedKeyInBytes.equals(HMAC256(givenKey, vararg));
    }
    /*
    public static String secretKeyToString(SecretKey key) {
        return Utils.encodeBytes(key.getEncoded());
    }

    public static SecretKey stringToSecretKey(String secretKey) {
        byte[] keyBytes = Utils.decodeBytes(secretKey.getBytes());
        System.out.println("didn't work");
		return new SecretKeySpec(keyBytes, "HmacSHA256");
    }*/

    

    /* 
    public static void main(String[] args) throws Exception {
		// https://www.devglan.com/online-tools/hmac-sha256-online
		String expected = "674b534088ba55e13908e3b7cbe97180f68697b1c47843ebe2efbc79c2623b65";
        Boolean isTrue = Digest.HMAC256("11A47EC4465DD95FCD393075E7D3C4EB", "testing...").equals(expected);
        System.out.println(isTrue);

        expected = "3113ecc824d5ee852cf4aa6c47a8957058327ddb4e8e673d1191bac49b35e084";
        isTrue = Digest.HMAC256("b1141653cf58a57d7f62c234a922f272849514610c345f2e5701006aad73a17b").equals(expected);
		System.out.println(isTrue);
        
	} */
}
