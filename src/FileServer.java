/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;


import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

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

public class FileServer extends Server {

    public static FileList fileList;
    public static byte[] pubKey;
    public static byte[] priKey;
    String filePubBase;

    public FileServer(int _port) {
        super(_port, "omega");
    }

    public String checkFile(String base){
        int counter = 0;
        String fname = base;
        File f = new File(fname);
        while(f.exists()){
            fname = base + String.valueOf(counter);
            f = new File(fname); 
            counter++;
        }

        return fname;
    }

    public void start() {
        String fileFile = "FileList.bin";
        filePubBase = "../../../file-pub.bin";
        String filePriBase = "../../../file-pri.bin";
        ObjectInputStream fileStream;


        // TODO: use File.Exist to check if public/private key already exist
        // if it already exists increment by 1 also add a config file
        // so the user knows which server is fileserver 1 and which server is fileserver
        // 2 
       
        String filePub = checkFile(filePubBase);
        String filePri = checkFile(filePriBase);

        try{
            RSA rsax = new RSA();
            rsax.generateKeys();

            /* Export private and public key */
            this.pubKey = rsax.savePubKey();
            this.priKey  = rsax.savePriKey();

            Utils.saveByteArr(this.pubKey, filePub);
            Utils.saveByteArr(this.priKey, filePri);

            System.out.println("Using public key " + filePub);
        }catch(Exception e){
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        
        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);


        // For the sake of the demo the file servers will not reuse the same keys

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("FileList Does Not Exist. Creating FileList...");

            fileList = new FileList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        File file = new File("shared_files");
        if (file.mkdir()) {
            System.out.println("Created new shared_files directory");
        } else if (file.exists()) {
            System.out.println("Found shared_files directory");
        } else {
            System.out.println("Error creating shared_files directory");
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread {
    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }
            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
