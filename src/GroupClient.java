/* Implements the GroupClient Interface */

import auth.token.*;
import crypto.Utils;

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;    
import javax.crypto.SealedObject;
import crypto.*;

public class GroupClient extends Client implements GroupClientInterface {

    byte[] filekey;
    int n;

    protected GroupClient() throws Exception {
        super();
    }
    
    public boolean getKey(String groupname, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to give group key
            outgoing = new Envelope("KGROUP");
            outgoing.addObject(groupname); //Add the group name string
            outgoing.addObject(token); //Add the requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }

            //If server indicates success, return true
            if (incoming.msgMatches("OK")) {
                ArrayList<Object> temp = null;
                temp = incoming.getObjContents();

                if(temp.size() == 2) {
                    filekey = (byte[])temp.get(0);
                    n  = (int)temp.get(1);
                }

                System.out.println("FILEKEY = " + this.filekey);
                System.out.println("N = " + this.n);
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    // Theat 1 sol
    public UserToken getToken(String username, byte[] privatekey, String file_key_path) {
        try {
            UserToken token = null;
            byte[] challenge = null;
            Envelope incoming = null, outgoing = null;

            //Tell the server to return a challenge.
            outgoing = new Envelope("GET");
            outgoing.addObject(username); //Add user name string

            outgoing.addObject(file_key_path); //Add user name string
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));


            //Decrypt envelope and get the challenge from the server
            
            //System.out.println("MADE IT HERE 1");
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                //System.out.println("MADE IT HERE X");
                output.writeObject(new Envelope("DISCONNECT"));
                return null;
            }

            //System.out.println("MADE IT HERE 2");
            //incoming.printMsg();

            //Successful response
            if (incoming.msgMatches("OK")) {
               // System.out.println("MADE IT HERE X1");
                ArrayList<Object> temp = null;
                temp = incoming.getObjContents();

                if(temp.size() == 1) {
                    challenge = (byte[])temp.get(0);
                }
            }

            //System.out.println("MADE IT HERE 3");
            // Decrypt the challenge
            byte[] decrypted = RSA.decryptWithKey(RSA.loadPriKey(privatekey), challenge);
            //System.out.println("MADE IT HERE 4");

            //Tell the server to return a token.
            outgoing = new Envelope("GET");
            outgoing.addObject(decrypted); //Add the decrypted challenge
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt and get the response from the server
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return null;
            }

           // System.out.println("DECRYPTED CHALLENEGE " + new String(decrypted));
            //Successful response
            if (incoming.msgMatches("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = incoming.getObjContents();

                if(temp.size() == 1) {
                    token = (UserToken)temp.get(0);
                    return token;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, UserToken token) {
        /* Check if the token is in the ADMIN group */
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to create a user
            outgoing = new Envelope("CUSER");
            outgoing.addObject(username); //Add user name string
            outgoing.addObject(token); //Add the requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }
  
            //If server indicates success, return true
            if (incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        /* Check if the token is in the ADMIN group */
        try {
            Envelope incoming = null, outgoing = null;

            //Tell the server to delete a user
            outgoing = new Envelope("DUSER");
            outgoing.addObject(username); //Add user name
            outgoing.addObject(token);  //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }
            //If server indicates success, return true
            if (incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
    TODO:
        - Flag owner associated to the token as the owner? 
    */
    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to create a group
            outgoing = new Envelope("CGROUP");
            outgoing.addObject(groupname); //Add the group name string
            outgoing.addObject(token); //Add the requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }

            //If server indicates success, return true
            if (incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
    TODO:
        - Delete group only if the user of the token is the owner
    */
    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to delete a group
            outgoing = new Envelope("DGROUP");
            outgoing.addObject(groupname); //Add group name string
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }

            incoming.printMsg();

            //If server indicates success, return true
            if (incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to return the member list
            outgoing = new Envelope("LMEMBERS");
            outgoing.addObject(group); //Add group name string
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));
            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return null;
            }

            incoming.printMsg();

            //If server indicates success, return the member list
            if (incoming.msgMatches("OK")) {


                List<String> tmp =  (List<String>)incoming.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
    //            for(String x : tmp){
  //                  System.out.println("Got user " + x);
//                }

                return tmp;
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    /**
    TODO: 
        - Check if the token is associated with the owner of the group
        - Reject any groupnames that already exist
    */
    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to add a user to the group
            outgoing = new Envelope("AUSERTOGROUP");
            outgoing.addObject(username); //Add user name string
            outgoing.addObject(groupname); //Add group name string
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }
            //If server indicates success, return true
            if(incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    /**
    TODO: 
        - Check if the token is associated with the owner of the group
            - If yes :
                - If the username is the owner of the group
                    - Remove all other users from the group
                    - Remove user from group 
        
    */
    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope incoming = null, outgoing = null;
            //Tell the server to remove a user from the group
            outgoing = new Envelope("RUSERFROMGROUP");
            outgoing.addObject(username); //Add user name string
            outgoing.addObject(groupname); //Add group name string
            outgoing.addObject(token); //Add requester's token
            output.writeObject(Envelope.encrypt(get_sequence_key(), outgoing, this.iv));

            //Decrypt envelope 
            incoming = Envelope.decrypt(get_sequence_key(), input.readObject(), this.iv);

            // Envelope was tampered with; abort
            if (incoming == null) {
                output.writeObject(new Envelope("DISCONNECT"));
                return false;
            }

            //If server indicates success, return true
            if(incoming.msgMatches("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

}
