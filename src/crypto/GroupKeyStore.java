package crypto;

import java.math.BigInteger;
import java.security.Provider;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import java.util.Random;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SealedObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.BadPaddingException;
import java.io.Serializable;


import java.io.*;
import java.util.*;


class GroupKey implements java.io.Serializable {
    private static final long serialVersionUID = 8600343803523452342L;
    public String gName;
    public byte[] key;
    public byte[] n_key;
    public int n;          /* n will be set to 20 to save time */

    public GroupKey(String gName){
        /* Create the AES key for the Group */
        try {
            SecretKey aes_key = AES.genKey();
            
            this.gName = gName;
            this.key = AES.getBytes(aes_key);
            this.n_key = AES.hashKey(this.key, 20);
            this.n = 20;

        }catch(Exception e){
        }
    }

    public synchronized void update(){
        try{
            this.n--;
            this.n_key = AES.hashKey(this.key, this.n);
        }catch(Exception e){
        }
    }
}


public class GroupKeyStore implements java.io.Serializable{
    private static final long serialVersionUID = 8600343803563417992L;
	private Hashtable<String, GroupKey> h = new Hashtable<String, GroupKey>();

    public synchronized void addKey(String groupname){
        this.h.put(groupname, new GroupKey(groupname));
    }

    public synchronized GroupKey getKey(String groupname){
        return this.h.get(groupname);
    }
    
    public synchronized byte[] getNKey(String groupname){
        return this.h.get(groupname).n_key;
    }

    public synchronized int getN(String groupname){
        return this.h.get(groupname).n;
    }

    public synchronized void removeKey(String groupname){
        this.h.remove(groupname);
    }

    public synchronized void updateKey(String groupname){
        this.h.get(groupname).update();
    }
}

