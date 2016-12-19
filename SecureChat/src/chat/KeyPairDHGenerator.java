package chat;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.spec.DHParameterSpec;


public class KeyPairDHGenerator {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private DHParameterSpec dhSpec;
    private BigInteger g = new BigInteger(
                    "7961C6D7913FDF8A034593294FA52D6F8354E9EDFE3EDC8EF082D36662D69DFE8CA7DC7480121C98B9774DFF915FB710D79E1BCBA68C0D429CD6B9AD73C0EF20",
                    16);
    private BigInteger p = new BigInteger(
                    "00AC86AB9A1F921B251027BD10B93D0A8D9A260364974648E2543E8CD5C48DB4FFBEF0C3843465BA8DE20FFA36FFAF840B8CF26C9EB865BA184642A5F84606AEC5",
                    16);
            
    public KeyPairDHGenerator(int keylength) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException{
        this.keyGen = KeyPairGenerator.getInstance("DiffieHellman");
        this.keyGen.initialize(keylength);
        //this.dhSpec= new DHParameterSpec(p, g, keylength);
        //this.keyGen.initialize(dhSpec);
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
}
