package chat;


import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.DHPublicKeySpec;

public class ConvertKeys {

    public static PrivateKey StringToPrivateKey(String chavePrivadaString) throws GeneralSecurityException {
        byte[] clear = Base64.getDecoder().decode(chavePrivadaString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("DSA");
        PrivateKey priv = fact.generatePrivate(keySpec);
        Arrays.fill(clear, (byte) 0);
        return priv;
    }

//    public static PublicKey StringToPublicKey(String chavePublicaString) throws GeneralSecurityException {
//        byte[] data = chavePublicaString.getBytes();
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
//        KeyFactory fact = KeyFactory.getInstance("DSA");
//        return fact.generatePublic(spec);
//    }
//    
//    public static PublicKey StringToPublicKey2(String chavePublicaString) throws NoSuchAlgorithmException, InvalidKeySpecException {
//        byte[] bytes = chavePublicaString.getBytes();
//        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
//    }
    public static PublicKey StringToPublicKey(String key) {
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePublic(X509publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static PublicKey StringToPublicKeyDH(String key) {
        BigInteger g = new BigInteger(
                "7961C6D7913FDF8A034593294FA52D6F8354E9EDFE3EDC8EF082D36662D69DFE8CA7DC7480121C98B9774DFF915FB710D79E1BCBA68C0D429CD6B9AD73C0EF20",
                16);
        BigInteger p = new BigInteger(
                "00AC86AB9A1F921B251027BD10B93D0A8D9A260364974648E2543E8CD5C48DB4FFBEF0C3843465BA8DE20FFA36FFAF840B8CF26C9EB865BA184642A5F84606AEC5",
                16);
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            DHPublicKeySpec dhspec = new DHPublicKeySpec(new BigInteger(byteKey), p, g);
            KeyFactory keyFact = KeyFactory.getInstance("DiffieHellman");
            return keyFact.generatePublic(dhspec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
    
    public static PublicKey StringToPublicKeyDH2(String key){
        try{
            byte[] byteKey = Base64.getDecoder().decode(key);
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(byteKey);
            return keyFactory.generatePublic(keySpec); // THROWS EXCEPTION
  
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey StringToPrivateKey2(String key) {
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec pkcs8privateKey = new PKCS8EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(pkcs8privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

//    public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
//        KeyFactory fact = KeyFactory.getInstance("DSA");
//        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
//                PKCS8EncodedKeySpec.class);
//        byte[] packed = spec.getEncoded();
//        String key64 = base64Encode(packed);
//
//        Arrays.fill(packed, (byte) 0);
//        return key64;
//    }
//    public static String savePublicKey(PublicKey publ) throws GeneralSecurityException {
//        KeyFactory fact = KeyFactory.getInstance("DSA");
//        X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);
//        return base64Encode(spec.getEncoded());
//    }
}
