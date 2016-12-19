package chat;

import java.security.Key;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CC {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    private final void readCC() throws Exception {
        //Lê o CC no leitor
        
        // get providers
        Provider[] provs = Security.getProviders();
        Provider cc = null;

        // find CC card
        for (int i = 0; i < provs.length; i++) {
            if (provs[i].getName().equals("SunPKCS11-CartaoCidadao")) {
                cc = provs[i];
                break;
            }
        }
        
        // get certificates
        KeyStore ks = KeyStore.getInstance("PKCS11", cc);
        ks.load(null, null);

        Certificate authCert = ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        
        // get public-key
        publicKey = authCert.getPublicKey();        
        
        // get private-key
        Key key = ks.getKey("CITIZEN AUTHENTICATION CERTIFICATE", "0".toCharArray());
        privateKey = (PrivateKey) key;
        
        //get cc name and number
        if (authCert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) authCert;
            Principal principal = x509cert.getSubjectDN();
            String subjectDn = principal.getName();
            String[] splited = subjectDn.split(", ");
            String nome = splited[0].split("=")[1];
            String ccNumber = splited[1].split("=")[1];
        }
    }
    
    private final byte[] signRSA(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(message);
        return signature.sign();
    }

    private final boolean checkSignature(byte[] message, byte[] sig, PublicKey publicKey) throws Exception {
        Signature signature;

        signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sig);
    }

    public final byte[] passwordEncrypt(byte[] password, byte[] data) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(password, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        
        return cipher.doFinal(data);
    }

    public final byte[] passwordDecrypt(byte[] password, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(password, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        
        return cipher.doFinal(encrypted);
    }

    private final byte[] rsaEncrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        return cipher.doFinal(data);
    }

    private final byte[] rsaDecrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
      
        return cipher.doFinal(data);
    }
}
