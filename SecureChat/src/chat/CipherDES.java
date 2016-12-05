package chat;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CipherDES {
    public static Scanner sc = new Scanner(System.in);
    
    public static byte[] cypherMsg(byte[] cm, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, sk);
        
        byte[] cifrado = c.doFinal(cm);
        
        return cifrado;
    }
}