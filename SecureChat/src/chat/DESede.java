package chat;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
        int keyLen = 192;  //24 bytes * 8 bits = 192 (tamanho da chave-bits)
        byte[] data = KeyDerivation.deriveKey(password, salt, keyLen);
        SecretKey desKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(data));
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(String password, byte[] salt, byte[] encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        int keyLen = 192;  //24 bytes * 8 bits = 192 (tamanho da chave-bits)
        byte[] data = KeyDerivation.deriveKey(password, salt, keyLen);
        SecretKey desKey = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(data));
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        return cipher.doFinal(encryptedText);
    }

    public static byte[] encryptSecureRandom(byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeySpecException {
        byte[] bytesRandom = new byte[20];
        SecureRandom.getInstanceStrong().nextBytes(bytesRandom);

        SecretKey desKey = SecretKeyFactory.getInstance("DES").generateSecret(new DESedeKeySpec(bytesRandom));
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(plaintext);
    }
}
