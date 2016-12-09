package chat;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class KeyPairGerador {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    public KeyPairGerador(int keylength) throws NoSuchAlgorithmException{
        this.keyGen = KeyPairGenerator.getInstance("RSA");
        this.keyGen.initialize(keylength);
    }
    
    public void createKeys(){
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }
    
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
    
//    public static void generateKeys() {
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(4096);
//            
//            KeyPair keyPair = keyPairGenerator.genKeyPair();
//            privateK = keyPair.getPrivate();
//            publicK = keyPair.getPublic();
//
//        } catch (Exception e) {
//            System.err.println(e + "@generateAndSaveRSAKeys");
//        }
//    }

 
    
}
