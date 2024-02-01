import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import crypto.*;
import javax.crypto.SealedObject;
import java.security.KeyPair;
import crypto.ECDH_BC;

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;
    protected PublicKey pubKey; 
    protected PrivateKey priKey;
    protected SecretKey sessionKey;
    protected IvParameterSpec iv;
    protected static final int FAILURE_MAX = 5;
    protected int seq_num;
    private enum functions {
        get_sequence_key(false), 
        connect(false),
        disconnect(false);

        public final boolean debug;

        private functions(boolean debug) {
            this.debug = debug;
        }

    }

    protected Client() throws Exception {
        KeyPair kp = ECDH_BC.generateKeys();
        pubKey = kp.getPublic();
        priKey = kp.getPrivate();
        seq_num = 0;
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

     
        print_debug("PREINCREMENT " + seq_num + " " + Utils.secret_key_to_string(sessionKey), functions.get_sequence_key.debug);
        
        // derive a new symmetric session key by hmacing the the chained temporary hash key
        sessionKey = new SecretKeySpec(Digest.HMAC256(temp.getEncoded()), "HmacSHA256");
        seq_num++;

        print_debug("POSTINCREMENT " + Utils.secret_key_to_string(sessionKey), functions.get_sequence_key.debug);
        return sessionKey;
    }

    public boolean connect(final String server, final int port) {
        SecretKey secretKey = null;
        
        print_debug("attempting to connect", functions.connect.debug);
        try {
            sock = new Socket(server, port);
            if (sock.isConnected()) {

                /* Create streams for input and output */
                output = new ObjectOutputStream(sock.getOutputStream());
                input = new ObjectInputStream(sock.getInputStream());

                Envelope incoming;
                Envelope response = new Envelope("INIT-HANDSHAKE");
                response.addObject(pubKey);
                output.writeObject(response);

                while (true) {

                    incoming = (Envelope)input.readObject();
                    String msg = incoming.getMessage();

                    if (msg.equals("ACK-HANDSHAKE")) {

                        PublicKey serverPub = (PublicKey)incoming.getObjContents().get(0);
                        response = new Envelope("INIT-AGREEMENT");
                        // create secret symmetric key
                        secretKey = ECDH_BC.srcAgreement(priKey, serverPub);
                        // create symmetric ephemeral key
                        sessionKey = new SecretKeySpec(Digest.HMAC256(secretKey.getEncoded()), "HmacSHA256");
                        // create shared iv
                        iv = Utils.generateIV();
                        response.addObject(iv.getIV());

                    } else if (msg.equals("HANDSHAKE-COMPLETE")) {
                        print_debug("HANDSHAKE-COMPLETE", functions.connect.debug);
                        break;
                    }
                
                    else {
                        // an error occurred
                        response = new Envelope("HANDSHAKE-FAILED"); 
                        disconnect();
                        return false;
                    }

                    output.writeObject(response);
                }

                return true;
            }
            return false;

        } catch(Exception e) {
            print_debug("Error while connecting to server " + 
                            server + " via port " + port + ": " +
                             e.getMessage(), functions.connect.debug);
            e.printStackTrace(System.err);
            return false;
        } 
    }

    public boolean isConnected() {
        if (sock == null || !sock.isConnected()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect()  {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
            } catch(Exception e) {
                print_debug("Error: " + e.getMessage(), functions.disconnect.debug);
                e.printStackTrace(System.err);
            }
        }
    }

    public void print_debug(String msg, boolean debug_on) {
        if (debug_on) System.out.println(msg);
    }

}
