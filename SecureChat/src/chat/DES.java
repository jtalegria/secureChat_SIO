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
import javax.crypto.spec.SecretKeySpec;


public class DES {

    SecretKey sk;

    public DES() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(new SecureRandom());
        this.sk = kg.generateKey();
    }

    public byte[] cipherMsg(byte[] msgToCipher) throws IllegalBlockSizeException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.sk);
        byte[] textEncrypted = cipher.doFinal(msgToCipher);

        return textEncrypted;
    }

    public byte[] decipherMsg(byte[] msgToDecipher) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(Cipher.DECRYPT_MODE, sk);
        byte[] textDecrypted = desCipher.doFinal(msgToDecipher);

        return textDecrypted;
    }

    public byte[] cipherMsgGivenSecretKey(byte[] msgToCipher, SecretKey secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] textEncrypted = cipher.doFinal(msgToCipher);

        return textEncrypted;
    }

    public byte[] decipherMsgGivenSecretKey(byte[] msgToDecipher, byte[] secretKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        SecretKey key = new SecretKeySpec(secretKey, "DES");
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        desCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] textDecrypted = desCipher.doFinal(msgToDecipher);

        return textDecrypted;
    }

    public SecretKey getKey() {
        return this.sk;
    }
}