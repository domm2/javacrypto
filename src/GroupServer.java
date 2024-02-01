/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.*;
import java.math.*;
import auth.token.*;
import crypto.*;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;
    public CryptoKeyStore pubList;
    public GroupKeyStore groupKeys;
    public byte[] pubKey;
    public byte[] priKey;

    public GroupServer(int _port) {
        super(_port, "alpha");
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
        String groupFile = "GroupList.bin";
        String groupKeyFile = "GroupKeys.bin";
        String pubFile = "../../../PubList.bin";
        String groupPub = "../../../group-pub.bin";
        String groupPri = "../../../group-pri.bin";
        
        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;
        ObjectInputStream pubStream;
        ObjectInputStream gkStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        String username = "";
        String publickey = "";
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            userList = (UserList)userStream.readObject();
            
            FileInputStream fis1 = new FileInputStream(groupFile);
            groupStream = new ObjectInputStream(fis1);
            groupList = (GroupList)groupStream.readObject();

            FileInputStream fis2 = new FileInputStream(pubFile);
            pubStream = new ObjectInputStream(fis2);
            pubList = (CryptoKeyStore)pubStream.readObject();
            
            FileInputStream fis3 = new FileInputStream(groupKeyFile);
            gkStream = new ObjectInputStream(fis3);
            groupKeys = (GroupKeyStore)gkStream.readObject();

            this.pubKey = Utils.loadByteArr(groupPub);
            this.priKey = Utils.loadByteArr(groupPri);

        } catch(FileNotFoundException e) {
            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            username = console.next();

            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            userList = new UserList();
            userList.addUser(username);
            userList.addGroup(username, "ADMIN");
            userList.addOwnership(username, "ADMIN");
            
            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            groupList = new GroupList();
            groupList.addGroup(username, "ADMIN");

            try{
                // Create group server key pair
                RSA rsax = new RSA();
                rsax.generateKeys();

                /* Export private and public key */
                this.pubKey = rsax.savePubKey();
                this.priKey  = rsax.savePriKey();

                Utils.saveByteArr(this.pubKey, groupPub);
                Utils.saveByteArr(this.priKey, groupPri);
            }catch(Exception ex){
                System.err.println("Error: " + ex.getMessage());
                ex.printStackTrace(System.err);
            }

            // Create new adamin key pair
            pubList = new CryptoKeyStore();
            groupKeys = new GroupKeyStore();

            try{
                RSA rsa = new RSA();
                rsa.generateKeys();

                /* Export private and public key */
                byte[] adminPub = rsa.savePubKey();
                byte[] adminPri = rsa.savePriKey();

                Utils.saveByteArr(adminPub, "../../../" + username + "-pub.bin");
                Utils.saveByteArr(adminPri, "../../../" + username + "-pri.bin");

                pubList.addKey(username, adminPub);
                
                System.out.println("PUBLIC KEY: " + String.format("%040x", new BigInteger(1,adminPub)));
                System.out.println("PRIVATE KEY: " + String.format("%040x", new BigInteger(1,adminPri)));
            }catch(Exception ex){
            }
            
        } catch(IOException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                // DH
                
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

//This thread saves the user list
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_gs.groupList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(10000);
                //Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group, user lists, and public-key list ...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

                // Save the pubList perodically
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("../../../PubList.bin"));
                    outStream.writeObject(my_gs.pubList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

                // Save the groupKeys perodically
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("GroupKeys.bin"));
                    outStream.writeObject(my_gs.groupKeys);
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

