package chat;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class DES {

    public static byte[] cipherMsg(byte[] msgToCipher) throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException {

        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom());
        SecretKey sk = kg.generateKey();

        Cipher desCipher;

        // Create the cipher
        desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // Initialize the cipher for encryption
        desCipher.init(Cipher.ENCRYPT_MODE, sk);

        // Encrypt the text
        byte[] textEncrypted = desCipher.doFinal(msgToCipher);

        return textEncrypted;
    }

    public static byte[] decipherMsg(byte[] msgToDecipher) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom());
        SecretKey sk = kg.generateKey();

        Cipher desCipher;

        // Create the cipher
        desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        desCipher.init(Cipher.DECRYPT_MODE, sk);

        // Decrypt the text
        byte[] textDecrypted = desCipher.doFinal(msgToDecipher);
        return textDecrypted;
    }

}
