package chat;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class ConvertKeys {

    public static PublicKey StringToPublicKeyRSA(String key) {
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
        try {
            byte[] byteKey = Base64.getDecoder().decode(key);
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(byteKey);
            return keyFactory.generatePublic(keySpec);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}