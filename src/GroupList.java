/* This list represents the groups on the server */

import auth.token.*;

import java.util.ArrayList;
import java.util.Hashtable;

public class GroupList implements java.io.Serializable {
    private static final long serialVersionUID = 1234567L;
    public Hashtable<String, Group> list = new Hashtable<String, Group>();

    /*
    * NOTE: Similar to UserList, validation checks don't occur in GroupList (beyond the validation calls)
    * Lack of security is fine for this phase as stated in Phase 2 description
    */


    /**
    * Adds group to list and makes the user the group leader
    * <p>
    * @param    username    new owner
    * @param    groupname   new group
    */
    public synchronized void addGroup(String username, String groupname) {
        Group group = new Group(username);
        list.put(groupname, group);
    }

    /**
    * Removes group from list
    * <p>
    * @param    groupname   new group to delete
    */
    public synchronized void removeGroup(String groupname) {
        list.remove(groupname);
    }

    /**
    * Returns list of users from group 
    * <p>
    * @param    groupname   group to access
    * @return   list of members from group
    */
    public synchronized ArrayList<String> getUsers(String groupname) {
        return list.get(groupname).getUsers();
    }

    /**
    * Checks if user is the owner
    * <p>
    * @param    username    user to check
    * @param    groupname   groupname that's being checked for ownership
    * @return   true if user is the owner; false, otherwise
    */
    public synchronized boolean checkOwnership(String username, String groupname) {
        return list.get(groupname).checkOwnership(username);
    }

    /**
    * Checks if user is member
    * <p>
    * @param    username    user to check
    * @param    groupname   groupname that's being checked for membership
    * @return   true if user is a member; false, otherwise
    */
    public synchronized boolean checkMembership(String username, String groupname) {
        return list.get(groupname).checkMembership(username);
    }
        
    /**
    * Checks if group exists
    * <p>
    * @param    groupname   groupname that's being checked for existence
    * @return   true if group exists
    */
    public synchronized boolean checkGroup(String groupname) {
        return list.containsKey(groupname);
    }

    /**
    *
    Removes member from a group
    <p>

    If the user is the owner of the group, this method will automatically delete group 
    @param username     User to delete
    @param group        Group from which the user needs to be deleted from
    
    TODO:
        - Case: user is not owner of group
        - Case: user is owner of group
            - Remove each non-owner members from the group
            - Remove groupname from group list
            - Remove group name from owner
    */
    public synchronized void removeMember(String username, String groupname) {
        //TODO: Handle both cases
        list.get(groupname).removeUser(username);
    }

    /**
    * Adds user from group
    * <p>
    * @param    username    user to add
    * @param    groupname   group that the user is being add from
    */
    public synchronized void addMember(String username, String groupname) {
        list.get(groupname).addUser(username);
    }

    class Group implements java.io.Serializable  {
        private String owner;
        private ArrayList<String> users;

        private static final long serialVersionUID = -6699986336323323598L;
        /**
        * Constructor to create group with the user as the owner
        * <p>
        * @param    user    Requester to make group and new owner
        */
        public Group(String user) {

            users = new ArrayList<String>();
            users.add(user);
            owner = user;
        }

        /**
        * Returns users
        * <p>
        * @return    ArrayList of users from group
        */
        public ArrayList<String> getUsers() {
            return users;
        }

        /**
        * Returns if user is the owner
        * <p>
        * @param    username to check for ownership 
        * @return    true if user is the owner
        */
        public boolean checkOwnership(String username) {
            return username.equals(owner);
        }

        /**
        * Returns if user is a member
        * <p>
        * @param    username to check for membership
        * @return   true if user is a member
        */
        public boolean checkMembership(String username) {
            return users.contains(username);
        }

        /**
        * Adds user to group
        * <p>
        * @param    username to add to group
        */
        public void addUser(String username) {
            users.add(username);
        }
        
        /**
        * Removes user to group
        * <p>
        * @param    username to remove to group
        */
        public void removeUser(String username) {
            users.remove(username);

            System.out.println("USERS AFTER REMOVE");
            ArrayList<String> tmp = this.getUsers();
            for(String user : tmp){
                System.out.println(user);
            }
        }
    }
}
