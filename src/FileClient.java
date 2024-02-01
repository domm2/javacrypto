/* FileClient provides all the client functionality regarding the file server */

import auth.token.*;

import java.io.File;

import java.net.Socket;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.util.List;
import java.math.*;
import crypto.*;


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

import java.math.BigInteger;
import java.security.*;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.BadPaddingException;

public class FileClient extends Client implements FileClientInterface {

    protected FileClient() throws Exception {
        super();
    }
    
    public boolean challenge(String fpub, String username, byte[] user_pri_key){
        try {
            KeyPair dhpair = ECDH_BC.generateKeys();
            byte[] dh_pubkey = ECDH_BC.savePubKey(dhpair.getPublic());

            /* Encrypt the DH pubkey with fileserver pub key */
            byte[] encpubkey = RSA.encryptWithKey(RSA.loadPubKey(Utils.loadByteArr(fpub)), dh_pubkey);
        
            Envelope env = new Envelope("CHALLENGE"); //Success
            env.addObject(encpubkey);
            env.addObject(username);

            output.writeObject(Envelope.encrypt(get_sequence_key(), env, this.iv));
            env = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);
		    
            if (env.msgMatches("OK")) {
                /* Create our secrete key */
                byte[] file_dh_pub_enc  = (byte[])env.getObjContents().get(0); 
                byte[] file_dh_pub = RSA.decryptWithKey(RSA.loadPriKey(user_pri_key), file_dh_pub_enc);
                byte[] key = ECDH_BC.doECDH(file_dh_pub, dhpair.getPrivate());

                SecureRandom secran = new SecureRandom();
                byte[] IV = new byte[16];
                secran.nextBytes(IV);
                
                SecretKey aes_key = AES.setKey(key);

                System.out.println("SERCRET KEY: " + String.format("%040x", new BigInteger(1, key)));

                /* Test connection */
                String enc = AES.encrypt(aes_key, "Hello", new IvParameterSpec(IV));
                System.out.println("ENCRYPTED CHALLENGE " + enc);

                String dec = AES.decrypt(aes_key, enc, new IvParameterSpec(IV));
                System.out.println("DECRYPTED CHALLENGE " + dec);

                env = new Envelope("CHALLENGE");
                env.addObject(enc);
                env.addObject(IV);
                output.writeObject(Envelope.encrypt(get_sequence_key(), env, this.iv));

                /* Get the response */
                env = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                System.out.println("I GOT FROM FS " + (String) env.getObjContents().get(0));
                if(new String("Hello").equals((String) env.getObjContents().get(0))){
                    System.out.println("FILE SERVER PASSED CHALLENGE");
                    return true;
                }else{
                    System.out.println("FILE SERVER FAILED CHALLENGE");
                    return false;
                }

            } else {
                return false;
            }
        } catch (Exception e1) {
            e1.printStackTrace();
        }

        return false;
    }
    public boolean delete(String filename, UserToken token) {
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }
        Envelope incoming = null;
        Envelope outgoing = new Envelope("DELETEF"); //Success
        outgoing.addObject(remotePath);
        outgoing.addObject(token);
        try {
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }

            
            incoming.printMsg();

            if (incoming.msgMatches("OK")) {
                System.out.printf("File %s deleted successfully\n", filename);
            } else {
                System.out.printf("Error deleting file %s (%s)\n", filename, incoming.getMessage());
                return false;
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return true;
    }

    public boolean download(String sourceFile, String destFile, UserToken token, byte[] key, int n_key) {
        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        File file = new File(destFile);
        try {
            if (!file.exists()) {
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);
                Envelope incoming;
                Envelope outgoing = new Envelope("DOWNLOADF"); //Success
                outgoing.addObject(sourceFile);
                outgoing.addObject(token);
                output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);
                // Envelope was tampered with; abort
                if (incoming == null) {
                    output.writeObject(new Envelope("DISCONNECT"));
                    fos.close();
                    return false;
                }

                
                incoming.printMsg();

                while (incoming.getMessage().compareTo("CHUNK")==0) {
                    fos.write((byte[])incoming.getObjContents().get(0), 0, (Integer)incoming.getObjContents().get(1));
                    System.out.printf(".");
                    outgoing = new Envelope("DOWNLOADF"); //Success
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                    incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                    if (incoming == null) {
                        output.writeObject(new Envelope("DISCONNECT"));
                        fos.close();
                        return false;
                    }

                    incoming.printMsg();
                }
                fos.close();

                if(incoming.getMessage().compareTo("EOF")==0) {
                    fos.close();

                    AES.DecryptFile(key, destFile, this.iv, n_key);
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    outgoing = new Envelope("OK"); //Success
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else {
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, incoming.getMessage());
                    file.delete();
                    fos.close();
                    return false;
                }
            }

            else {
                System.out.printf("Error couldn't create file %s\n", destFile);
                return false;
            }


        } catch (IOException e) {
            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;

        } catch (ClassNotFoundException e) {
            e.printStackTrace();

        } catch (Exception e ) {
            e.printStackTrace();
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to return the member list
            outgoing = new Envelope("LFILES");
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return null;
            }

            
            incoming.printMsg();

            //If server indicates success, return the member list
            if(incoming.msgMatches("OK")) {
                return (List<String>)incoming.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group,
                          UserToken token, byte[] key, int n_key) {

        if (destFile.charAt(0)!='/') {
            destFile = "/" + destFile;
        }

        /* Delete temp file */
        File file = new File("output.txt");
        file.delete();
        
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to return the member list
            outgoing = new Envelope("UPLOADF");
            outgoing.addObject(destFile);
            outgoing.addObject(group);
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));


            System.out.println(token.getSubject() + " is upload a file");

            FileInputStream fis = new FileInputStream(AES.EncryptFile(key, sourceFile, this.iv, n_key));


            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            
            incoming.printMsg();

            //If server indicates success, return the member list
            if (incoming.msgMatches("READY")) {
                System.out.printf("Meta data upload successful\n");

            } else {

                System.out.printf("Upload failed: %s\n", incoming.getMessage());
                return false;
            }


            do {
                byte[] buf = new byte[4096];
                if (incoming.getMessage().compareTo("READY")!=0) {
                    System.out.printf("Server error: %s\n", incoming.getMessage());
                    return false;
                }
                outgoing = new Envelope("CHUNK");
                int n = fis.read(buf); //can throw an IOException
                if (n > 0) {
                    System.out.printf(".");
                } else if (n < 0) {
                    System.out.println("Read error");
                    return false;
                }

                outgoing.addObject(buf);
                outgoing.addObject(Integer.valueOf(n));

                output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));


                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                // Envelope was tampered with; abort
                if (incoming == null) {
                    output.writeObject(new Envelope("DISCONNECT"));
                    return false;
                }


            } while (fis.available()>0);

            //If server indicates success, return the member list
            if(incoming.getMessage().compareTo("READY") == 0) {

                outgoing = new Envelope("EOF");
                output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);
                    // Envelope was tampered with; abort
                if (incoming == null) {
                    output.writeObject(new Envelope("DISCONNECT"));
                    return false;
                }

                if(incoming.msgMatches("OK")) {
                    System.out.printf("\nFile data upload successful\n");

                } else {

                    System.out.printf("\nUpload failed: %s\n", incoming.getMessage());
                    return false;
                }

            } else {

                System.out.printf("Upload failed: %s\n", incoming.getMessage());
                return false;
            }

        } catch(Exception e1) {
            System.err.println("Error: " + e1.getMessage());
            e1.printStackTrace(System.err);
            return false;
        }
        return true;
    }

}
