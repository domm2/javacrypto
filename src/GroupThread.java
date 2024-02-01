/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */

import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.*;

import java.util.*;
import auth.token.*;
import crypto.*;

public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;
    public static CryptoKeyStore shTokenTable = new CryptoKeyStore();
    public PublicKey pubKey; // for ECDH
    private PrivateKey priKey; // for ECDH
    private SecretKey sessionKey;
    private SecretKey secretKey;
    private IvParameterSpec iv;
    private boolean encrypted;
    private int seq_num;


    public GroupThread(Socket _socket, GroupServer _gs) throws Exception {
        socket = _socket;
        my_gs = _gs;
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
        // Iterating through the Hashtable
        // object
 
        // Checking for next element in Hashtable object
        // with the help of hasMoreElements() method
            Enumeration<String> xw = my_gs.groupList.list.keys();
        while (xw.hasMoreElements()) {
 
            // Getting the key of a particular entry
            String key = xw.nextElement();
            // Print and display the Rank and Name
            
            GroupList.Group tmp = my_gs.groupList.list.get(key);

            System.out.println("USERS IN GROUP " + key);
            ArrayList<String> users   = tmp.getUsers();
            for(String user : users){
                System.out.println("I GOT USER " + user);
            }

        }

        /* TODO: Finish user creation via admin account
         * then add paraphrase to Driver
         * e.g. must decrypt private key bin before using */
        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
     

            do {
                Envelope incoming; 
                Envelope outgoing;

                if (encrypted == false) {
                    incoming = (Envelope)input.readObject();
                    incoming.printMsg();

                    if (incoming.msgMatches("INIT-HANDSHAKE")) {
                        PublicKey clientPub = (PublicKey) incoming.getObjContents().get(0);
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

                    continue; // ignore the remainder of the control block; still in handshake
                }

                incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);


                // Is ending the connection the best choice if tampering occurs?
                if (incoming == null) {
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                }

                incoming.printMsg();

                if (incoming.msgMatches("GET")) { //Client wants a token
                    String username = (String) incoming.getObjContents().get(0); //Get the username
                    String f_key_path = (String) incoming.getObjContents().get(1); //Get the f_key_path
                    System.out.println("HERE " + username);
                    System.out.println("FILE KEY PATH " + f_key_path);
                    if(username == null) {
                        System.out.println("HERE 1");
                        outgoing = new Envelope("FAIL");
                        outgoing.addObject(null);
                        output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                    } else {
                        System.out.println("HERE 2");
                        // Create a challenge with user's public key
                        byte[] chall = Utils.genChall();
                        System.out.println("CHALLANGE " + new String(chall));
                        byte[] enchall = RSA.encryptWithKey(RSA.loadPubKey(my_gs.pubList.getKey(username)), chall);

                        outgoing = new Envelope("OK");
                        outgoing.addObject(enchall);
                        // does output need to write response here and in lower control blocks?
                        output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                        System.out.println("HERE 3");

                        // Get the challange response
                        incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

                        if (incoming == null) {
                            socket.close(); //Close the socket
                            proceed = false; //End this communication loop
                        }

                        incoming.printMsg();


                        byte[] chreq = (byte[])incoming.getObjContents().get(0);
                        if((new String(chreq)).equals(new String(chall))){
                            System.out.println("CHALLANGE PASSED");
                            UserToken yourToken = createToken(username, f_key_path);
                            
                            outgoing = new Envelope("OK");
                            outgoing.addObject(yourToken);
                            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                        }else{

                            System.out.println("CHALLANGE FAILED");
                            outgoing = new Envelope("FAIL");
                            outgoing.addObject(null);
                            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                        }
                    }
                } else if(incoming.msgMatches("CUSER")) { //Client wants to create a user

                    if(incoming.getObjContents().size() < 2) {
                        outgoing = new Envelope("FAIL");
                        System.out.println("HERE 1");
                    } else {
                        outgoing = new Envelope("FAIL");

                        System.out.println("HERE 2");
                        if(incoming.getObjContents().get(0) != null) {
                            System.out.println("HERE 3");

                            if(incoming.getObjContents().get(1) != null) {
                                System.out.println("HERE 4");

                                String username = (String)incoming.getObjContents().get(0); //Extract the username
                                UserToken yourToken = (UserToken)incoming.getObjContents().get(1); //Extract the token

                                if (createUser(username, yourToken)) {
                                        outgoing = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }

                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else if(incoming.msgMatches("DUSER")) { //Client wants to delete a user

                    if(incoming.getObjContents().size() < 2) {
                        outgoing = new Envelope("FAIL");

                    } else {
                        outgoing = new Envelope("FAIL");

                        if (outgoing.getObjContents().get(0) != null) {
                            if (outgoing.getObjContents().get(1) != null) {
                                String username = (String)outgoing.getObjContents().get(0); //Extract the username
                                UserToken yourToken = (UserToken)outgoing.getObjContents().get(1); //Extract the token
                                
                                if(deleteUser(username, yourToken)) {
                                    outgoing = new Envelope("OK"); //Success
                                }
                            }
                        }
                    }

                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else if(incoming.msgMatches("CGROUP")) { //Client wants to create a group
                    outgoing = new Envelope("FAIL");
                    
                    if (incoming.getObjContents().size() >= 2) {
                        if (incoming.getObjContents().get(0) != null && incoming.getObjContents().get(1) != null) {
                            String group = (String)incoming.getObjContents().get(0); //Extract the group
                            UserToken yourToken = (UserToken)incoming.getObjContents().get(1); //Extract the token
                        
                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is creating GROUP: " + group);

                            if (createGroup(group, yourToken)) {
                                outgoing = new Envelope("OK");
                            }
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                } else if(incoming.msgMatches("KGROUP")) {
                    outgoing = new Envelope("FAIL");
                    
                    if (incoming.getObjContents().size() >= 2) {
                        if (incoming.getObjContents().get(0) != null && incoming.getObjContents().get(1) != null) {
                            String group = (String)incoming.getObjContents().get(0); //Extract the group
                            UserToken yourToken = (UserToken)incoming.getObjContents().get(1); //Extract the token
                        
                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is requesting key for GROUP: " + group);

                            if (getGroupKey(group, yourToken)) {
                                System.out.println(yourToken.getSubject() + " is request granted for GROUP: " + group);
                                outgoing = new Envelope("OK");
                                outgoing.addObject(my_gs.groupKeys.getNKey(group));
                                outgoing.addObject(my_gs.groupKeys.getN(group));
                            }
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
    
                } else if(incoming.msgMatches("DGROUP")) { //Client wants to create a group
                    outgoing = new Envelope("FAIL");

                    if (incoming.getObjContents().size() >= 2) {

                        if (incoming.getObjContents().get(0) != null && incoming.getObjContents().get(1) != null) {
                            String group = (String)incoming.getObjContents().get(0); //Extract the group
                            UserToken yourToken = (UserToken)incoming.getObjContents().get(1); //Extract the token
                            
                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is deleting GROUP: " + group);

                            if (deleteGroup(group, yourToken)) {
                                outgoing = new Envelope("OK");
                            }
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                //Client wants to list members of a group
                } else if (incoming.msgMatches("LMEMBERS")) { 

                    outgoing = new Envelope("FAIL");

                    if (incoming.getObjContents().size() >= 2) {
                        if (incoming.getObjContents().get(0) != null && incoming.getObjContents().get(1) != null) {
                            String group = (String)incoming.getObjContents().get(0); //Extract the group
                            UserToken yourToken = (UserToken)incoming.getObjContents().get(1); //Extract the token
                        
                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is listing members of GROUP: " + group);
                            
                            ArrayList<String> users = listMembers(group, yourToken);
                            output.reset();
                            if (users != null) {
                                for(String x : users){
                                    System.out.println("I GOT A USER " + x);
                                }
                                outgoing = new Envelope("OK");
                                outgoing.addObject(users); 
                            }

                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                //Client wants to add user to a group
                } else if (incoming.msgMatches("AUSERTOGROUP")) { 
                    outgoing = new Envelope("FAIL");
                    if (incoming.getObjContents().size() >= 3) {
                        if (incoming.getObjContents().get(0) != null &&
                                incoming.getObjContents().get(1) != null && incoming.getObjContents().get(2) != null) {

                            // Extract the new member
                            String user = (String) incoming.getObjContents().get(0); 

                            // Extract the group
                            String group = (String) incoming.getObjContents().get(1); 

                            // Extract the token
                            UserToken yourToken = (UserToken) incoming.getObjContents().get(2); 

                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is adding " + user + " to GROUP: " + group);

                            if (addUserToGroup(user, group, yourToken)) {
                                outgoing = new Envelope("OK");
                            }
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                //Client wants to remove user from a group
                } else if (incoming.msgMatches("RUSERFROMGROUP")) { 
                    outgoing = new Envelope("FAIL");

                    if (incoming.getObjContents().size() >= 3) {
                        
                        if (incoming.getObjContents().get(0) != null &&
                                incoming.getObjContents().get(1) != null && incoming.getObjContents().get(2) != null) {
                            
                            // Extract the new member
                            String user = (String) incoming.getObjContents().get(0); 

                            //Extract the group
                            String group = (String) incoming.getObjContents().get(1); 

                             //Extract the token
                            UserToken yourToken = (UserToken) incoming.getObjContents().get(2);
                            // DEBUG INFO
                            System.out.println(yourToken.getSubject() + " is deleting a member " + user + " from  GROUP: " + group);

                            if (deleteUserFromGroup(user, group, yourToken)) {
                                outgoing = new Envelope("OK");
                            }
                        }
                    }
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

                //Client wants to disconnect
                } else if (incoming.msgMatches("DISCONNECT")) { 
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop

                //Server does not understand client request
                } else {
                    outgoing = new Envelope("FAIL"); 
                    output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
                }
                output.reset();

            } while(proceed);
            
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    //Method to create tokens
    private UserToken createToken(String username, String f_key_path) {
        //Check that user exists
        if(my_gs.userList.checkUser(username)) {
            //gets fs pubkey
            PublicKey fsPub = RSA.loadPubKey(Utils.loadByteArr(f_key_path));
            //key to bytes to string
            String fsPubKey = Base64.getEncoder().encodeToString(fsPub.getEncoded());
            //Issue a new token with fs pub key, server's name, user's name, and user's groups
            UserToken yourToken = new UserToken(fsPubKey, my_gs.name, username, my_gs.userList.getUserGroups(username));
            
            //creates signed hash version of the token and stores it in hash table
            createSHToken(yourToken);

            return yourToken;
        } else {
            return null;
        }
    }
    
    //create signed hash token
    //store in hash table
    private void createSHToken(UserToken yourToken){
        byte[] shToken = SandH(yourToken);
        ObjectOutputStream outStream;
        //add newToken to hash table
        shTokenTable.addKey(yourToken.getIssuer(), shToken); //( username, signed hash token )
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("../../../shTokenTable.bin"));
            outStream.writeObject(shTokenTable);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }


    //helper class to hash and sign the token provided 
    //used to put in the hash table and check against the table
    //returns the signed hash token version 
    private byte[] SandH(UserToken yourToken){
        //serialize, hash, sign, verify
        byte[] shToken = null;

        try{
            String sToken = yourToken.getSToken(); //serialized in userToken.java
            byte[] hash_sToken = Utils.hash(sToken); //hashed
            Provider bc = new BouncyCastleProvider();

            Signature signed = Signature.getInstance("SHA256withRSA", bc);
            //use private key to sign 
            signed.initSign(RSA.loadPriKey(my_gs.priKey)); 
            signed.update(hash_sToken);
            shToken = signed.sign();
            System.out.println("Signed Hashed Token: " + shToken);
  
            //Verify the resulting RSA signature and print out whether the verification succeeded
            // signed.initVerify(RSA.loadPubKey(my_gs.pubKey)); 
            // Boolean result = signed.verify(signvalue);
            // System.out.println("Verified?: " + result);

        }catch(NoSuchAlgorithmException ex){ 
            System.err.println(ex);
        }catch(InvalidKeyException ex){ 
            System.err.println(ex);
        }catch(SignatureException ex){ 
            System.err.println(ex);
        }
        return shToken;
    }

    //everytime a token is provided with a request we must verify the token
    //returns true when the token matches the hash version 
    public boolean verifyToken(UserToken yourToken){

        //serialize, hash, sign, verify against table
        byte[] shToken = SandH(yourToken);
        System.out.println("Signed hash version of the token given: " + String.format("%040x", new BigInteger(1,shToken)));

        //compares shToken with shToken in the hash table
        byte[] originToken = shTokenTable.getKey(yourToken.getIssuer());
        System.out.println("signed hash version of original token assigned to user: " + String.format("%040x", new BigInteger(1,originToken)));
        if((new String(shToken)).equals((new String(originToken)))){
            return true;
        }
        System.out.println("origin token and given token do not match sorry");
        return false;
    }


    //Method to create a user
    private boolean createUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if(my_gs.userList.checkUser(requester) && verifyToken(yourToken)) {

            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if(temp.contains("ADMIN")) {
                //Does user already exist?
                if(my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username);
                    
                    // Right now it's okay to have the Group Server
                    // generate the keys for the users
                    // key distribution is not a problem for phase 3 implementation
                    // but it MUST BE addressed in the writeup
                    // Users should generate their own keys and send it to the GroupServer
                    // securly. 
                    try{
                        RSA rsa = new RSA();
                        rsa.generateKeys();
                        /* Export private and public key */
                        byte[] adminPub = rsa.savePubKey();
                        byte[] adminPri = rsa.savePriKey();

                        /* We will be opearting on a shared drive, so keys should easily be 
                         * accesable */
                        Utils.saveByteArr(adminPub, "../../../" + username + "-pub.bin");
                        Utils.saveByteArr(adminPri, "../../../" + username + "-pri.bin");
                        
                        my_gs.pubList.addKey(username, adminPub);
                    }catch(Exception e){
                        System.err.println("Error: " + e.getMessage());
                        e.printStackTrace(System.err);
                    }
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    //Method to delete a user
    private boolean deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist? and token authentic? 
        if(my_gs.userList.checkUser(requester) && verifyToken(yourToken)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if(temp.contains("ADMIN")) {
                //Does user exist?
                if(my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new UserToken(my_gs.name, username, deleteOwnedGroup));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    return true;
                } else {
                    return false; //User does not exist

                }
            } else {
                return false; //requester is not an administer
            }
        } else {
            return false; //requester does not exist
        }
    }

   /**
    * Helper method for the run method 
    * <p>
    * Checks if the requester can delete a group and delete the group if it exists and the requester is the owner
    *
    * @param    group       name of group requester wants to create
    * @param    token       token of requester
    * @return   true if requester can remove a group; false, otherwise
    */
    private boolean deleteGroup(String group, UserToken token) {
        String requester = token.getSubject();
        //Does requester exist? and token authentic?
        if(my_gs.userList.checkUser(requester) && verifyToken(token)) {
            System.out.println("HERE 1");
            // Does the group exist and is the user the owner?
            if (my_gs.groupList.checkGroup(group) && my_gs.groupList.checkOwnership(requester, group)) { 
                System.out.println("HERE 2");
                ArrayList<String> users = my_gs.groupList.getUsers(group);
                for (String user: users) { // removes group from users
                    my_gs.userList.removeGroup(user, group);
                }
                my_gs.groupList.removeGroup(group); // remove group from group list
                return true;
            }   
        } return false; // group didn't exist of user was not valid
    }

    private boolean getGroupKey(String group, UserToken token) {
        if (token == null) return false;
        String requester = token.getSubject();

        /* Check if the user exist and token is authentic*/
        if (my_gs.userList.checkUser(requester) && verifyToken(token)) {
            /* Check if the group exist */
            if (my_gs.groupList.checkGroup(group)) {
                if(my_gs.groupList.checkMembership(requester, group)){
                    return true;
                }
                return false; 
            }
        } return false; // group already existed or user was not valid
    }

   /**
    * Helper method for the run method 
    * <p>
    * Checks if the requester can create a group and creates the group if it doesn't already exist
    *
    * @param    group       name of group requester wants to create
    * @param    token       token of requester
    * @return   GroupKey if requester can create a new group; null, otherwise
    */
    private boolean createGroup(String group, UserToken token) {
        if (token == null) return false;
        String requester = token.getSubject();

        /* Check if the user exist and token is authentic*/
        if (my_gs.userList.checkUser(requester) && verifyToken(token)) {
            /* Check if the group exist */
            if (!my_gs.groupList.checkGroup(group)) {
                
                my_gs.groupList.addGroup(requester, group);
                my_gs.userList.addGroup(requester, group);
                my_gs.groupKeys.addKey(group);

                return true; // group created
            }
        } return false; // group already existed or user was not valid
    }

   /**
    * Helper method for the run method
    * <p>
    * Checks if the user of the token can list members
    * 
    * @param    group       group the user wants to list members of
    * @param    token       token of requester
    * @return   ArrayList of users from group if it exists and the the requester is on the userlist and a member of the group             
    */
    private ArrayList<String> listMembers(String group, UserToken token) {
        if (token == null){
            System.out.println("null token");
            return null;
        }
        String requester = token.getSubject();
        // Does the requester exist? and token authentic?
        if(my_gs.userList.checkUser(requester) && verifyToken(token)) { 
            System.out.println("HERE 1");
            // Does the group exist and is the requester the owner?
            if (my_gs.groupList.checkGroup(group) && my_gs.groupList.checkOwnership(requester, group)) {
                System.out.println("HERE 2");
                return my_gs.groupList.getUsers(group);
            }
        } return null; // group doesn't exist or requester failed validation
    }

    /**
    * Helper method for the run method 
    * <p>
    * Checks if the requester can add another user to the group
    *
    * @param    user        user to add to group
    * @param    group       group the requester wants to add user to
    * @param    token       token of requester
    * @return   true if requester is the owner of the group and can add the other user; false, otherwise
    */
    private boolean addUserToGroup(String user, String group, UserToken token) {
        String requester = token.getSubject();
        // does the requester exist and user exist? and token authentic?
        if (my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(user) && verifyToken(token)) {
            // does the group exist and is the requester the owner?
            if (my_gs.groupList.checkGroup(group) && my_gs.groupList.checkOwnership(requester, group)) {
                my_gs.groupList.addMember(user, group); // add member to group
                my_gs.userList.addGroup(user, group); // add group to user
                return true;
            }
        } return false; // group did not exist or requester failed validation
    }

    /**
    * Helper method for the run method 
    * <p>
    * Checks if the requester can remove another user to the group
    * Removes user from group
    *
    * @param    user        user to remove to group
    * @param    group       group the requester wants to remove user to
    * @param    token       token of requester
    * @return   true if requester is the owner of the group and can remove the other user; false, otherwise
    */
    private boolean deleteUserFromGroup(String user, String group, UserToken token) {
        String requester = token.getSubject();
        // does the requester exist? and the token authentic?
        if (my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(user) && verifyToken(token)) {
             // does the group exist and is the requester the owner?
            if (my_gs.groupList.checkGroup(group) && my_gs.groupList.checkOwnership(requester, group)) {
                if (requester.equals(user)) { // requester is the owner and wants to delete everything
                    System.out.println(requester + " is deleting entire group GROUP: " + group);
                    ArrayList<String> users = my_gs.groupList.getUsers(group);
                    for (String member: users) { 
                        my_gs.userList.removeGroup(member, group); // delete group from the user's list
                    }
                    my_gs.groupList.removeGroup(group); // remove the group from the group list
                    my_gs.groupKeys.removeKey(group); // remove the group key from the keys list
                    return true;
                }
                // owner wants to delete another member
                System.out.println(requester + " is removing another member: " + user);
                my_gs.userList.removeGroup(user, group);
                my_gs.groupList.removeMember(user, group);
                my_gs.groupKeys.updateKey(group); // update the group key

                return true;
            }
        } return false; // group did not exist or requester failed validation
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
