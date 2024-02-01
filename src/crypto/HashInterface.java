package crypto;

public interface HashInterface {

    public String hash(String message);

    public String verifyHash(String hashedMessage, String toVerify); 

}