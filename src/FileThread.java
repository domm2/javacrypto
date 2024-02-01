/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import auth.token.*;

import java.util.*;
import java.lang.Thread;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.*;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.*;
import crypto.*;
import auth.token.*;

import java.util.ArrayList;
import java.lang.Thread;
import java.net.Socket;
import java.security.InvalidKeyException;
import javax.crypto.SealedObject;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SealedObject;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.*;

import crypto.*;

public class FileThread extends Thread {
    private final Socket socket;
    private FileServer my_fs;
    public PublicKey pubKey; // for ECDH
    private PrivateKey priKey; // for ECDH
    private SecretKey sessionKey;
    private SecretKey secretKey;
    private IvParameterSpec iv;
    private boolean encrypted;
    private int seq_num;

    public FileThread(Socket _socket, FileServer _fs) throws Exception {
        socket = _socket;
        my_fs = _fs;
        KeyPair kp = ECDH_BC.generateKeys();
        pubKey = kp.getPublic();
        priKey = kp.getPrivate();
        secretKey = null;
        sessionKey = null;
        encrypted = false;
        iv = null;
        seq_num = 0;
    }

    public void run() {
        boolean proceed = true;
        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            

            do {
                Envelope incoming;
                Envelope outgoing;

                /** 
                 * HANDSHAKE
                */
                if (encrypted == false) {
                    incoming = (Envelope)input.readObject();
                    incoming.printMsg();


                    if (incoming.msgMatches("INIT-HANDSHAKE")) {
                        PublicKey clientPub = (PublicKey)incoming.getObjContents().get(0);

                        outgoing = new Envelope("ACK-HANDSHAKE");
                        outgoing.addObject(pubKey);

                        secretKey = ECDH_BC.srcAgreement(priKey, clientPub);
                        sessionKey = new SecretKeySpec(Digest.HMAC256(secretKey.getEncoded()), "HmacSHA256");
                        output.writeObject(outgoing);

                    }

                    else if (incoming.msgMatches("INIT-AGREEMENT")) {
                        // get shared iv
                        iv = new IvParameterSpec((byte[]) incoming.getObjContents().get(0));
                        outgoing = new Envelope("HANDSHAKE-COMPLETE");
                        output.writeObject(outgoing);
                        encrypted = true;

                    }

                    else if (incoming.msgMatches("HANDSHAKE-FAILED")) {
                        socket.close(); //Close the socket
                        proceed = false; //End this communication loop
                    }
                    continue;
                }

                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                
                // Is ending the connection the best choice if tampering occurs?
                if (incoming == null) {
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                }

                incoming.printMsg();

                // Handler to list files that this user is allowed to see
                if (incoming.msgMatches("LFILES")) {

                    UserToken t = (UserToken) incoming.getObjContents().get(0);
                    System.out.println("Request received token from: " + t.getSubject());

                    //if token is not authenticated
                    if(! verifyTokenfs(t)){ 
                        outgoing = new Envelope("FAIL-FALSE-TOKEN");
                    }

                    List<String> g = t.getGroups();

                    ArrayList<ShareFile> shar = FileServer.fileList.getFiles();
                    List<String> out = new ArrayList<String>();

                    /* Check if the file belongs to one of the groups the user can access */
                    for(String x : g){
                        for(ShareFile s : shar){
                            if(x.equals(s.getGroup())){
                                /* If we can acces it add to output array */
                                out.add(s.getPath());
                            }
                        }
                    }

                    outgoing = new Envelope("OK"); //Success
                    outgoing.addObject(out);
                   
                    /* Send to socket */
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                }

                else if (incoming.msgMatches("UPLOADF")) {

                    if(incoming.getObjContents().size() < 3) {
                        outgoing = new Envelope("FAIL-BADCONTENTS");
                    } else {
                        if(incoming.getObjContents().get(0) == null) {
                            outgoing = new Envelope("FAIL-BADPATH");
                        }
                        if(incoming.getObjContents().get(1) == null) {
                            outgoing = new Envelope("FAIL-BADGROUP");
                        }
                        if(incoming.getObjContents().get(2) == null) {
                            outgoing = new Envelope("FAIL-BADTOKEN");

                        } else {
                            String remotePath = (String)incoming.getObjContents().get(0);
                            String group = (String)incoming.getObjContents().get(1);
                            UserToken yourToken = (UserToken)incoming.getObjContents().get(2); //Extract token
                            //if token is not authenticated

                            if(! verifyTokenfs(yourToken)){ 
                                outgoing = new Envelope("FAIL-FALSE-TOKEN");
                            }
                            //is the token being used to see if this action is permitted ? 

                            if (FileServer.fileList.checkFile(remotePath)) {
                                System.out.printf("Error: file already exists at %s\n", remotePath);
                                outgoing = new Envelope("FAIL-FILEEXISTS"); //Success

                            } else if (!yourToken.getGroups().contains(group)) {
                                System.out.printf("Error: user missing valid token for group %s\n", group);
                                outgoing = new Envelope("FAIL-UNAUTHORIZED"); //Success

                            } else  {
                                File file = new File("shared_files/"+remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

                                outgoing = new Envelope("READY"); //Success
                                output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                                // Is ending the connection the best choice if tampering occurs?
                                if (incoming == null) {
                                    socket.close(); //Close the socket
                                    proceed = false; //End this communication loop
                                }

                                incoming.printMsg();

                                while (incoming.msgMatches("CHUNK")) {
                                    fos.write((byte[])incoming.getObjContents().get(0), 0, (Integer)incoming.getObjContents().get(1));
                                    outgoing = new Envelope("READY"); //Success
                                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                                    incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                                    // Is ending the connection the best choice if tampering occurs?
                                    if (incoming == null) {
                                        socket.close(); //Close the socket
                                        proceed = false; //End this communication loop
                                    }

                                    incoming.printMsg();
                                }

                                

                                if (incoming.msgMatches("EOF")) {
                                    System.out.printf("Transfer successful file %s\n", remotePath);
                                    FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
                                    outgoing = new Envelope("OK"); //Success

                                } else {
                                    System.out.println("WE GOT ");
                                    incoming.printMsg();
                                    System.out.println("END OF WHAT WE GOT");
                                    System.out.printf("Error reading file %s from client\n", remotePath);
                                    outgoing = new Envelope("ERROR-TRANSFER"); //Success
                                }
                                fos.close();
                            }
                        }
                    }

                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else if (incoming.msgMatches("DOWNLOADF")) {

                    String remotePath = (String) incoming.getObjContents().get(0);
                    UserToken t = (UserToken) incoming.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

                    if (sf == null) {
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        outgoing = new Envelope("ERROR_FILEMISSING");
                        output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));


                    //if token is not authenticated
                    } else if(! verifyTokenfs(t)){ 
                        System.out.printf("Token does not belong to user %s \n", t.getSubject());
                        outgoing = new Envelope("FAIL-FALSE-TOKEN");
                    
                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        outgoing = new Envelope("ERROR_PERMISSION");
                        output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                    } else {

                        try {
                            File f = new File("shared_files/_"+remotePath.replace('/', '_'));
                            if (!f.exists()) {
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                outgoing = new Envelope("ERROR_NOTONDISK");
                                output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                            } else {
                                FileInputStream fis = new FileInputStream(f);

                                do {
                                    byte[] buf = new byte[4096];
                                    if (incoming.getMessage().compareTo("DOWNLOADF")!=0 ){
                                        System.out.printf("Server error: %s\n", incoming.getMessage());
                                        break;
                                    }
                                    outgoing = new Envelope("CHUNK");
                                    int n = fis.read(buf); //can throw an IOException
                                    if (n > 0) {
                                        System.out.printf(".");
                                    } else if (n < 0) {
                                        System.out.println("Read error");

                                    }


                                    outgoing.addObject(buf);
                                    outgoing.addObject(Integer.valueOf(n));

                                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                                    incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                                    // Is ending the connection the best choice if tampering occurs?
                                    if (incoming == null) {
                                        socket.close(); //Close the socket
                                        proceed = false; //End this communication loop
                                    }

                                    incoming.printMsg();



                                } while (fis.available()>0);

                                //If server indicates success, return the member list
                                if (incoming.getMessage().compareTo("DOWNLOADF")==0) {

                                    outgoing = new Envelope("EOF");
                                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                                    incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                                    // Is ending the connection the best choice if tampering occurs?
                                    if (incoming == null) {
                                        socket.close(); //Close the socket
                                        proceed = false; //End this communication loop
                                    }

                                    incoming.printMsg();


                                    if(incoming.msgMatches("OK")) {
                                        System.out.printf("File data upload successful\n");

                                    } else {

                                        System.out.printf("Upload failed: %s\n", incoming.getMessage());

                                    }

                                } else {
                                    System.out.printf("Upload failed: %s\n", incoming.getMessage());
                                }
                            }
                        } catch(Exception e1) {
                            System.err.println("Error: " + incoming.getMessage());
                            e1.printStackTrace(System.err);

                        }
                    }
                } else if (incoming.msgMatches("DELETEF")) {

                    
                    String remotePath = (String) incoming.getObjContents().get(0);
                    UserToken t = (UserToken) incoming.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

                    if (sf == null) {
                        System.out.printf("Error: File %s doesn't exist\n", remotePath);
                        outgoing = new Envelope("ERROR_DOESNTEXIST");
                        //authenticate token

                    }else if(! verifyTokenfs(t)){ 
                        System.out.printf("Token does not belong to user %s \n", t.getSubject());
                        outgoing = new Envelope("FAIL-FALSE-TOKEN");

                    }else if (!t.getGroups().contains(sf.getGroup())) {
                        System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                        outgoing = new Envelope("ERROR_PERMISSION");
                        
                    } else {

                        try {
                            File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

                            if (!f.exists()) {
                                System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                outgoing = new Envelope("ERROR_FILEMISSING");

                            } else if (f.delete()) {
                                System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
                                FileServer.fileList.removeFile("/"+remotePath);

                                outgoing = new Envelope("OK");
                            } else {
                                System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
                                outgoing = new Envelope("ERROR_DELETE");

                            }


                        } catch(Exception e1) {
                            System.err.println("Error: " + e1.getMessage());
                            e1.printStackTrace(System.err);
                            outgoing = new Envelope(e1.getMessage());
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else if(incoming.msgMatches("DISCONNECT")) {
                    socket.close();
                    proceed = false;

                } else if(incoming.msgMatches("CHALLENGE")) {
                    KeyPair dhpair = ECDH_BC.generateKeys();

                    /* Get the ECDH public key from the client */
                    byte[] enc_client_dh_pubkey = (byte[]) incoming.getObjContents().get(0);
                    String username = (String) incoming.getObjContents().get(1);

                    byte[] client_dh_pubkey = RSA.decryptWithKey(RSA.loadPriKey(FileServer.priKey), enc_client_dh_pubkey);

                    /* Encrypt file server dh pub key for client and send */
                    byte[] dh_pubkey = ECDH_BC.savePubKey(dhpair.getPublic());

                    byte[] enc_dh_pubkey = RSA.encryptWithKey(RSA.loadPubKey(Utils.loadByteArr("../../../" + username + "-pub.bin")), dh_pubkey);
                    outgoing = new Envelope("OK");
                    outgoing.addObject(enc_dh_pubkey);
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                    /* Generate AES key */
                    byte[] key = ECDH_BC.doECDH(client_dh_pubkey, dhpair.getPrivate());
                    
                    SecretKey aes_key = AES.setKey(key);
                
                    System.out.println("SERCRET KEY: " + String.format("%040x", 
                            new BigInteger(1, key)));
                    
                    /* Get the test message */
                    incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);
                    String msg = (String) incoming.getObjContents().get(0);
                    byte[] iv = (byte[]) incoming.getObjContents().get(1);

                    /* Send the decrypted test message */
                    outgoing = new Envelope("OK");
                    String dec = AES.decrypt(aes_key, msg, new IvParameterSpec(iv));
                    System.out.println("DECRYPT STUFF BEFORE " + msg);
                    System.out.println("DECRYPT STUFF " + dec);
                    outgoing.addObject(dec);
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                } 
                 
            } while(proceed);

        } catch(Exception message) {
            message.printStackTrace(System.err);
        }
    }

    //everytime a token is provided with a request we must verify the token
    //returns true when the token matches the hash version 
    private boolean verifyTokenfs(UserToken yourToken) throws Exception{

        String sToken = yourToken.getSToken(); //serialized in userToken.java

        //TODO: check if pubkey matches 
        PublicKey thisFSKey = RSA.loadPubKey(Utils.loadByteArr(my_fs.filePubBase));
        String thisFS = Base64.getEncoder().encodeToString(thisFSKey.getEncoded());

        //if this fs pubkey != token fs pub key return false 
        if(!thisFS.equals(yourToken.getFsPub())) return false; 

        byte[] hash_sToken = Utils.hash(sToken); //hashed
        System.out.println("hash version of the token given: " + String.format("%040x", new BigInteger(1,hash_sToken)));

        //original token in the table signed and hashed 
        //should we be using the issuer attached to this token provided or the user provided??
        //this token could be the right token for the given user but the user providing this token might not match 
        
        
        FileInputStream fis = new FileInputStream("../../../shTokenTable.bin");
        ObjectInputStream userStream;
        CryptoKeyStore TokenTable;
        userStream = new ObjectInputStream(fis);
        TokenTable = (CryptoKeyStore)userStream.readObject();
        byte [] originToken = TokenTable.getKey(yourToken.getIssuer());
        System.out.println("signed hash version of original token assigned to user: " + String.format("%040x", new BigInteger(1,originToken)));

        //unsign the origin token 
        //compare/verify unsigned hashed tokens   
        userStream.close();     
        return unsignToken(originToken, hash_sToken); 
    }

    //helper function to unsign the signed hash token in the hashtable
    private boolean unsignToken(byte [] originToken, byte[] hash_sToken){
        
        try{
            Provider bc = new BouncyCastleProvider();

            Signature signed = Signature.getInstance("SHA256withRSA", bc);
            //use public key to verify 
            signed.initVerify(RSA.loadPubKey(Utils.loadByteArr("../../../group-pub.bin"))); 
            signed.update(hash_sToken);
            // byte[] hash_originToken = null;
           // hash_originToken = signed.sign();
            //System.out.println("UNsigned hash version of original token assigned to user: " + new String(hash_originToken));

            Boolean result = signed.verify(originToken);
            System.out.println("Verified?: " + result);
            return result;

        }catch(NoSuchAlgorithmException ex){ 
            System.err.println(ex);
        }catch(InvalidKeyException ex){ 
            System.err.println(ex);
        }catch(SignatureException ex){ 
            System.err.println(ex);
            ex.printStackTrace();
        }
        return false;
    }

    protected SecretKey get_sequence_key() throws Exception {
        // prepend sequence number to shared session key
        byte[] prepended_bytes = Utils.concatenate_bytes(String.valueOf(seq_num).getBytes(), sessionKey.getEncoded());

        // derive temporary key from the hmac of the newly forced elliptic curve key
        byte[] new_key_bytes = Digest.HMAC256(ECDH_BC.savePriKey(ECDH_BC.loadPriKey(prepended_bytes)));
        SecretKey temp = new SecretKeySpec(new_key_bytes, "HmacSHA256");

        // chain hash the temporary key
        for (int i = 0; i < seq_num + 1; i++) {
            new_key_bytes = Utils.hash(Utils.secret_key_to_string(temp));
            temp = new SecretKeySpec(new_key_bytes, "HmacSHA256");
        }

        // derive a new symmetric session key by hmacing the the chained temporary hash key
        sessionKey = new SecretKeySpec(Digest.HMAC256(temp.getEncoded()), "HmacSHA256");
        seq_num++;

        return sessionKey;
    }
}
