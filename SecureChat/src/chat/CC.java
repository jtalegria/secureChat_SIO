package chat;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CC {

    public Certificate getCertificate() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
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

        String assinaturaCertLabel = "CITIZEN SIGNATURE CERTIFICATE";
        Certificate certificate = ks.getCertificate(assinaturaCertLabel);

        return certificate;
    }

    public String signMsg(byte[] msg) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableKeyException,
            InvalidKeyException, SignatureException {

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

        String assinaturaCertLabel = "CITIZEN SIGNATURE CERTIFICATE";

        Certificate cert = ks.getCertificate(assinaturaCertLabel);

        PrivateKey privkey = (PrivateKey) ks.getKey(assinaturaCertLabel, "user".toCharArray());


        /* sign */
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign((PrivateKey) privkey);
        sig.update(msg);
        String assinatura = Base64.getEncoder().encodeToString(sig.sign());

        return assinatura;
    }

    public String getName() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        String name = "";
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
        if (authCert instanceof X509Certificate) {
            X509Certificate x509cert = (X509Certificate) authCert;
            Principal principal = x509cert.getSubjectDN();
            String subjectDn = principal.getName();
            String[] splited = subjectDn.split(", ");
            name = splited[0].split("=")[1];
        }
        return name;
    }

    public String getPublicKeyStringGivenCertificate(Certificate certificate) {
        PublicKey pKey = certificate.getPublicKey();
        byte[] pKeyArray = pKey.getEncoded();
        String pKeyString = Base64.getEncoder().encodeToString(pKeyArray);

        return pKeyString;
    }

    public Certificate getCertificateGivenString(String certificateString) throws CertificateException {
        byte[] certificateArray = Base64.getDecoder().decode(certificateString);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificateArray);
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(in);

        return certificate;
    }
}
