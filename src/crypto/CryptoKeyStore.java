package crypto;

import java.io.*;
import java.util.*;

public class CryptoKeyStore implements java.io.Serializable{
    private static final long serialVersionUID = 8600343803563417992L;
	private Hashtable<String, byte[]> h = new Hashtable<String, byte[]>();

    public synchronized void addKey(String username, byte[] key){
        this.h.put(username, key);
    }

    public synchronized byte[] getKey(String username){
        return this.h.get(username);
    }

    public synchronized void removeKey(String username){
        this.h.remove(username);
    }
}

