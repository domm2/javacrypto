package auth.token;


import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.io.Serializable;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public class UserToken implements UserTokenInterface, Serializable {

    private String groupServer;
    private String username;
    private ArrayList<String> userGroups;
    String fsPubkey;

    public UserToken(String sname, String uname, ArrayList<String> groups) {
        this.groupServer = sname;
        this.username = uname;
        this.userGroups = groups;
        Collections.sort(userGroups); //sort groups to keep order when hashing
    }
    public UserToken(String fsPubkey, String sname, String uname, ArrayList<String> groups) {
        this.fsPubkey = fsPubkey;
        this.groupServer = sname;
        this.username = uname;
        this.userGroups = groups;
        Collections.sort(userGroups); //sort groups to keep order when hashing
    }


    public String getIssuer() {
        String out = groupServer;
        return out;
    }

    public String getSubject() {
        String out = username;
        return out;
    }
    
    public String getFsPub() {
        String out = fsPubkey;
        return out;
    }

    public List<String> getGroups() {
        List<String> out = new ArrayList<String>();
        Collections.sort(userGroups); //sort groups to keep order when hashing
        for (String group: userGroups) { // deep copy user groups
            out.add(group);
        }
        return out;
    }

    public String getSToken(){
        StringBuilder sToken = new StringBuilder();

        //`fspubkey.sname.uname.groups[0].groups[n]`
        sToken.append(fsPubkey + "."); 
        sToken.append(groupServer + ".");
        sToken.append(username + ".");
        for(String group: userGroups){
            sToken.append(group + ".");
        }

        String final_sToken = sToken.toString();

        System.out.println("SERIALIZED TOKEN IN UserToken.java = " + final_sToken);

        return final_sToken;
    }

}  
