import java.util.ArrayList;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import crypto.AES;
import crypto.Digest;
import java.lang.StringBuilder;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import crypto.Utils;
import java.io.IOException;

public class Envelope implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7726335089122193103L;
    private String msg;
    private ArrayList<Object> objContents = new ArrayList<Object>();
    private ArrayList<String> objChecksums;

    public Envelope(String text) {
        msg = text;
    }

    public void printMsg() {
        System.out.println("Request received: " + msg);
    }

    public String getMessage() {
        return msg;
    }

    public boolean msgMatches(String otherMsg) {
        return msg.equals(otherMsg);
    }

    public ArrayList<Object> getObjContents() {
        return objContents;
    }

    private ArrayList<String> getChecksums() {
        return objChecksums;
    }

    private void setChecksums(final ArrayList<String> checksums) {
        objChecksums = checksums;
    }

    public void addObject(Object obj) {
        objContents.add(obj);
        //addChecksum(obj);
    }

    public static String objToChecksum(Object item) throws IOException, NoSuchAlgorithmException {
        String checksum = "";
        ByteArrayOutputStream byte_stream;
        ObjectOutputStream out_stream;
        if (item == null) return checksum;

        byte_stream = new ByteArrayOutputStream();
        
        try {
            out_stream = new ObjectOutputStream(byte_stream);
            out_stream.writeObject(item);
            
            checksum = Utils.bytesToHex(Utils.hash(byte_stream.toString()));
            out_stream.close();
            byte_stream.close();

        } catch (java.io.IOException e) {
            System.out.println("Error adding checksum");
        }

        return checksum;
    }

    // Validates the checksum from the given objects
    public static boolean checksumValid(ArrayList<Object> objContents, ArrayList<String> objChecksums) throws Exception {
        int contents_size = objContents.size();
        if (objContents == null || objChecksums == null) return false;
        if (contents_size != objChecksums.size()) return false;

        for (int i = 0; i < contents_size; i++) {
            Object curr = objContents.get(i);
            if (curr == null) return false;
            String curr_checksum = objToChecksum(curr);
            if (!curr_checksum.equals(objChecksums.get(i))) {
                return false;
            }
        }
        return true;
    }

    // encrypted the envelope into a sealed object given a shared session key and iv
    public static SealedObject encrypt(SecretKey session_key, Envelope plain_env, IvParameterSpec iv) throws Exception {
        ArrayList<String> checksums = new ArrayList<String>();
        // attach the checksums to the envelope
        for (Object obj: plain_env.getObjContents()) {
            checksums.add(objToChecksum(obj));
        }
        plain_env.setChecksums(checksums);

        return AES.encrypt(session_key, plain_env, iv);
    }

    // decrypts the given envelope 
    public static Envelope decrypt(SecretKey session_key, Object encrypted_env, IvParameterSpec iv) throws Exception {
        if (encrypted_env == null) return null;
        Envelope decrypted = (Envelope) AES.decrypt(session_key, (SealedObject) encrypted_env, iv);
        if (decrypted == null) return null;
        if (!checksumValid(decrypted.getObjContents(), decrypted.getChecksums())) return null; // check integrity; throw away message if tampered with

        return decrypted;
    }
}