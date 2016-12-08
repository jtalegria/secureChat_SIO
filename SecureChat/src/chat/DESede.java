package chat;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class DESede {

    public static byte[] encrypt(String password, byte[] salt, byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeySpecException {
        byte[] data = KeyDerivation.deriveKey(password, salt, 192);
        SecretKey desKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(data));
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(String password, byte[] salt, byte[] encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] data = KeyDerivation.deriveKey(password, salt, 192);
        SecretKey desKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(data));
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        return cipher.doFinal(encryptedText);
    }
}
