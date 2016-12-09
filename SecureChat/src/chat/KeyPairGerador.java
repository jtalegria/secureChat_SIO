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
    static PrivateKey privateK;
    static PublicKey publicK;
    
    public static void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateK = keyPair.getPrivate();
            publicK = keyPair.getPublic();

        } catch (Exception e) {
            System.err.println(e + "@generateAndSaveRSAKeys");
        }
    }

    public static PrivateKey getPrivateKey() {
        return privateK;
    }

    public static PublicKey getPublicKey() {
        return publicK;
    }
    
}
