package chat;


import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecureChat_Main {

    // Classe cliente
    static Scanner sc = new Scanner(System.in);
    static Socket socket;
    static BufferedReader in;
    static InputStream inStream;
    static PrintStream out;
    static byte[] buffer = new byte[1024];
    static int l;
    static int limitDelimiter = 1;
    static boolean registoViaCC = false;
    static KeyPairRSAGenerator parDeChavesRSA;
    static KeyPairDHGenerator parDeChavesDH;
    static PublicKey publicKeyCC;
    static Certificate certificateCC;
    static DES des;
    static String nomeCliente;
    static String username = "Nao Definido";
    static String randomNumber = getSecureRandom();
    static HashMap<String, String> usernameClientes = new HashMap<>();
    static HashMap<String, HashMap<byte[], String>> clientKeysPassword = new HashMap<>();
    static HashMap<String, SecretKey> clientKeysDH = new HashMap<>();
    static HashMap<String, SecretKey> clientKeysPublicKey = new HashMap<>();
    static CC cc = new CC();

    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {
        socket = new Socket("localhost", 1025);
        System.out.println(" >> Conexão estabelecida no porto 1025.");

        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();

        in = new BufferedReader(new InputStreamReader(input));
        out = new PrintStream(output);
        inStream = socket.getInputStream();

        while (true) {
            menu();
            while (true) {
                // Verifica qualquer input do Utilizador
                if (System.in.available() != 0) {
                    menuInicial();
                    menu();
                }

                if (inStream.available() != 0) {
                    JsonReader jReader = new JsonReader(in);
                    JsonElement jElement = new JsonParser().parse(jReader);
                    JsonObject jObject = jElement.getAsJsonObject();
                    String remetente = jObject.get("remetente").getAsString();

                    if (jObject.get("ID").getAsString().equals("all")) {
                        System.out.println("\n>> Recebeu uma nova mensagem de " + remetente + " (Enviada para todos os Utilizadores)!");
                        System.out.println(">> Mensagem : " + jObject.get("msg").getAsString());
                        break;
                    } else if (jObject.get("ID").getAsString().equals("DESede")) {
                        //DECIFRAR DES

                        System.out.println("\n>> Recebeu uma nova mensagem de " + remetente + " (Cifrada Simetricamente)!");
                        System.out.print("Password para ver mensagem: ");

                        sc.nextLine();
                        String pwd = sc.nextLine();

                        JsonObject resultObject = jObject.get("msg").getAsJsonObject();
                        String msgBody = resultObject.get("msgBody").getAsString();
                        String salt = resultObject.get("salt").getAsString();

                        String toMAC = msgBody.concat(salt);

                        String newMAC = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(toMAC, pwd));

                        String receivedMAC = jObject.get("HMAC").getAsString();

                        if (newMAC.equals(receivedMAC)) {
                            byte[] saltArray = Base64.getDecoder().decode(resultObject.get("salt").getAsString());
                            byte[] msgToDecipher = Base64.getDecoder().decode(resultObject.get("msgBody").getAsString());

                            String msgDecifrada = new String(DESede.decrypt(pwd, saltArray, msgToDecipher));
                            System.out.println(">> Verificacao valida! Mensagem: " + msgDecifrada);
                        } else {
                            System.out.println("MACs diferentes!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("cifraHibrida")) {
                        // DECIFRAR A CIFRA HIBRIDA
                        des = new DES();
                        System.out.println("\n>> Recebeu uma nova mensagem de " + remetente + " (Cifrada Hibridamente)!");

                        byte[] chaveSimetricaCifrada = Base64.getDecoder().decode(jObject.get("chave").getAsString());
                        byte[] msgToDecipher = Base64.getDecoder().decode(jObject.get("msg").getAsString());

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();

                        String registoViaCC = result.get("registoViaCC").getAsString();
                        // -- Validacao da Assinatura

                        byte[] assinaturaRemetente = Base64.getDecoder().decode(jObject.get("assinatura").getAsString());

                        boolean signatureVerification;
                        if (registoViaCC.equals("true")) {
                            String certificadoString = result.get("certificadoCC").getAsString();
                            Certificate certificado = cc.getCertificateGivenString(certificadoString);
                            String chavePublicaRemetente = cc.getPublicKeyStringGivenCertificate(certificado);
                            
                            Signature sig = Signature.getInstance("SHA1WithRSA");
                            sig.initVerify(ConvertKeys.StringToPublicKeyRSA(chavePublicaRemetente));
                            sig.update(msgToDecipher);
                            signatureVerification = sig.verify(assinaturaRemetente);

                        } else {
                            String chavePublicaRemetente = result.get("publicKeyRSA").getAsString();
                            Signature sig = Signature.getInstance("SHA1WithRSA");
                            sig.initVerify(ConvertKeys.StringToPublicKeyRSA(chavePublicaRemetente));
                            sig.update(msgToDecipher);
                            signatureVerification = sig.verify(assinaturaRemetente);
                        }
                        if (signatureVerification == true) {
                            System.out.println("Assinatura valida!");
                            //3) Decifra da chave
                            PrivateKey myPrivate = parDeChavesRSA.getPrivateKey();

                            byte[] chaveSimetricaDecifrada = CipherAssimetricKeys.decipher(myPrivate, chaveSimetricaCifrada);

                            //4) Decifra da msg
                            byte[] msgDecifradaArray = des.decipherMsgGivenByteArraySecretKey(msgToDecipher, chaveSimetricaDecifrada);

                            String msgDecifrada = new String(msgDecifradaArray);
                            
                            System.out.println(">> Mensagem: " + msgDecifrada);
                            break;
                        } else {
                            System.out.println("Assinatura invalida!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("acordoChavesPublicKey")) {
                        byte[] secretKeyCifrada = Base64.getDecoder().decode(jObject.get("chaveSessao").getAsString());
                        byte[] secretKeyDecifrada = CipherAssimetricKeys.decipher(parDeChavesRSA.getPrivateKey(), secretKeyCifrada);

                        SecretKey sk = new SecretKeySpec(secretKeyDecifrada, 0, secretKeyDecifrada.length, "DESede");

                        if (!clientKeysPublicKey.containsKey(remetente)) {
                            clientKeysPublicKey.put(remetente, sk);
                            System.out.println("Chave de Sessao estabelecida com " + remetente);
                        } else {
                            System.out.println("Chaves de Sessao nao definidas");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("envioMsgPublicKey")) {
                        des = new DES();
                        byte[] msgToDecipher = Base64.getDecoder().decode(jObject.get("msg").getAsString());
                        byte[] assinaturaRemetente = Base64.getDecoder().decode(jObject.get("assinatura").getAsString());

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();

                        String registoViaCC = result.get("registoViaCC").getAsString();

                        boolean signatureVerification;
                        if (registoViaCC.equals("true")) {
                            String certificadoString = result.get("certificadoCC").getAsString();
                            Certificate certificado = cc.getCertificateGivenString(certificadoString);
                            String chavePublicaRemetente = cc.getPublicKeyStringGivenCertificate(certificado);
                            
                            
                            Signature sig = Signature.getInstance("SHA1WithRSA");
                            sig.initVerify(ConvertKeys.StringToPublicKeyRSA(chavePublicaRemetente));
                            sig.update(msgToDecipher);
                            signatureVerification = sig.verify(assinaturaRemetente);

                        } else {
                            String chavePublicaRemetente = result.get("publicKeyRSA").getAsString();
                            Signature sig = Signature.getInstance("SHA1WithRSA");
                            sig.initVerify(ConvertKeys.StringToPublicKeyRSA(chavePublicaRemetente));
                            sig.update(msgToDecipher);
                            signatureVerification = sig.verify(assinaturaRemetente);
                        }

                        if (signatureVerification == true) {
                            System.out.println("Assinatura valida! Mensagem proveniente de " + remetente);
                            byte[] msgDecifrada = des.decipherMsgGivenByteArraySecretKey(msgToDecipher, clientKeysPublicKey.get(remetente).getEncoded());
                            System.out.println(">> Mensagem: " + new String(msgDecifrada));

                            if (new String(msgDecifrada).equals("ENCERRAR")) {
                                clientKeysPublicKey.remove(remetente);
                                System.out.println("Acordo de chaves terminado!");
                            }
                        } else {
                            System.out.println("Assinatura invalida!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("acordoChavesDH")) {
                        byte[] secretKeyCifrada = Base64.getDecoder().decode(jObject.get("chaveSessao").getAsString());
                        byte[] secretKeyDecifrada = CipherAssimetricKeys.decipher(parDeChavesDH.getPrivateKey(), secretKeyCifrada);

                        SecretKey sk = new SecretKeySpec(secretKeyDecifrada, 0, secretKeyDecifrada.length, "DES");

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();
                        String chavePublicaRemetente = result.get("publicKeyDH").getAsString();

                        KeyAgreement ka;
                        ka = KeyAgreement.getInstance("DiffieHellman");
                        ka.init(parDeChavesDH.getPrivateKey());
                        PublicKey publicKeyDestinatarioDH = ConvertKeys.StringToPublicKeyDH(chavePublicaRemetente);
                        ka.doPhase(publicKeyDestinatarioDH, true);
                        SecretKey secretKey = ka.generateSecret("DES");

                        if (sk == secretKey) {
                            if (!clientKeysDH.containsKey(remetente)) {
                                clientKeysDH.put(remetente, sk);
                                System.out.println("Chave de Sessao estabelecida com " + remetente);
                            } else {
                                System.out.println("Chaves de Sessao nao definidas");
                            }
                        } else {
                            System.out.println("Acordo de Chaves Distinto!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("envioMsgDH")) {
                        des = new DES();
                        byte[] msgToDecipher = Base64.getDecoder().decode(jObject.get("msg").getAsString());
                        byte[] assinaturaRemetente = Base64.getDecoder().decode(jObject.get("assinatura").getAsString());

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();
                        String chavePublicaRemetente = result.get("publicKeyDH").getAsString();

                        Signature sig = Signature.getInstance("SHA1WithRSA");
                        sig.initVerify(ConvertKeys.StringToPublicKeyDH(chavePublicaRemetente));
                        sig.update(msgToDecipher);
                        boolean signatureVerification = sig.verify(assinaturaRemetente);

                        if (signatureVerification == true) {
                            System.out.println("Assinatura valida! Mensagem proveniente de " + remetente);
                            byte[] msgDecifrada = des.decipherMsgGivenByteArraySecretKey(msgToDecipher, clientKeysDH.get(remetente).getEncoded());
                            System.out.println(">> Mensagem: " + new String(msgDecifrada));
                            if (new String(msgDecifrada).equals("ENCERRAR")) {
                                clientKeysDH.remove(remetente);
                                System.out.println("Acordo de chaves terminado!");
                            }
                        } else {
                            System.out.println("Assinatura invalida!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("acordoChavesPassword")) {
                        System.out.println("\n>> Definir acordo de chaves com " + remetente);
                        System.out.print("Password: ");

                        sc.nextLine();
                        String pwd = sc.nextLine();

                        String digestReceived = jObject.get("chaveSessao").getAsString();

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();
                        String randomNumberRecebido = result.get("randomNumber").getAsString();

                        String toDigestString = pwd.concat(randomNumberRecebido).concat(randomNumber);

                        byte[] toDigestArray = toDigestString.getBytes();

                        MessageDigest sha = MessageDigest.getInstance("MD5");
                        byte[] digest = sha.digest(toDigestArray);
                        digest = Arrays.copyOf(digest, 8);

                        String digestNew = Base64.getEncoder().encodeToString(digest);

                        if (digestReceived.equals(digestNew)) {
                            if (!clientKeysPassword.containsKey(remetente)) {
                                HashMap<byte[], String> tmp = new HashMap<>();
                                tmp.put(digest, pwd);
                                clientKeysPassword.put(remetente, tmp);
                                System.out.println("Chave de Sessao estabelecida com " + remetente);
                            } else {
                                System.out.println("Chaves de Sessao nao definidas");
                            }
                        } else {
                            System.out.println("Acordo de Chaves Distinto!");
                        }
                        break;
                    } else if (jObject.get("ID").getAsString().equals("envioMsgPassword")) {
                        des = new DES();
                        String msgToDecipherString = jObject.get("msg").getAsString();
                        byte[] msgToDecipherArray = Base64.getDecoder().decode(jObject.get("msg").getAsString());

                        out.println("{\"command\":\"list\",\"id\":\"" + remetente + "\"}");
                        JsonReader jReader2 = new JsonReader(in);
                        JsonElement jElement2 = new JsonParser().parse(jReader2);
                        JsonObject jObject2 = jElement2.getAsJsonObject();

                        JsonArray resultArray = jObject2.get("result").getAsJsonArray();
                        JsonObject result = resultArray.get(0).getAsJsonObject();

                        HashMap<byte[], String> tmp = clientKeysPassword.get(remetente);
                        byte[] digest = null;
                        String pwd = null;

                        for (Map.Entry<byte[], String> entry : tmp.entrySet()) {
                            digest = entry.getKey();
                            pwd = entry.getValue();
                        }

                        String receivedMac = jObject.get("HMAC").getAsString();
                        String newMAC = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(msgToDecipherString, pwd));

                        if (receivedMac.equals(newMAC)) {
                            System.out.println("Verificacao valida! Mensagem proveniente de " + remetente);
                            byte[] msgDecifrada = des.decipherMsgGivenByteArraySecretKey(msgToDecipherArray, digest);
                            System.out.println(">> Mensagem: " + new String(msgDecifrada));
                            if (new String(msgDecifrada).equals("ENCERRAR")) {
                                clientKeysDH.remove(remetente);
                                System.out.println("Acordo de chaves terminado!");
                            }
                        } else {
                            System.out.println("Assinatura invalida!");
                        }
                        break;
                    }
                }
                Thread.currentThread().sleep(200); // 100 milis
            }
        }
    }

    public static void menu() throws IOException {
        System.out.println("");
        System.out.println("--- MENU ---");
        System.out.println("1 - Registar Cliente");
        System.out.println("2 - Listar Cliente \"online\"");
        System.out.println("3 - Enviar mensagem");
        System.out.println("4 - Sair");
        System.out.println("");

        System.out.println("--------------");
        System.out.print("Insira a opcao: ");
    }

    public static void menuInicial() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {
        boolean quit = false;
        int menuItem;

        menuItem = sc.nextInt();
        System.out.println("------------");
        switch (menuItem) {
            case 1:
                registar();
                break;
            case 2:
                printSelections();
                break;
            case 3:
                sendSelections();
                break;
            case 4:
                System.exit(0);
            default:
                System.out.println("Opcao invalida.");
        }

    }

    public static void registar() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            KeyStoreException, CertificateException, UnrecoverableKeyException {
        Scanner scanner = new Scanner(System.in);

        System.out.println(">> 1 - Registo via CC - Insirir previamente");
        System.out.println(">> 2 - Registo padrão");
        System.out.print(">> Opcao: ");
        int op = scanner.nextInt();
        scanner.nextLine();
        switch (op) {
            case 1:
                registoViaCC = true;
                if (limitDelimiter == 1) {
                    parDeChavesRSA = new KeyPairRSAGenerator(1024);
                    parDeChavesRSA.createKeys();
                    byte[] publicKeyRSAArray = parDeChavesRSA.getPublicKey().getEncoded();
                    String publicKeyRSA = Base64.getEncoder().encodeToString(publicKeyRSAArray);

                    //publicKeyCC = cc.getPublicKey();
                    certificateCC = cc.getCertificate();
                    byte[] certificateCCArray = certificateCC.getEncoded();
                    String certificateCCString = Base64.getEncoder().encodeToString(certificateCCArray);
                    //byte[] publicKeyCCArray = publicKeyCC.getEncoded();
                    //String publicKeyCCString = Base64.getEncoder().encodeToString(publicKeyCCArray);

                    //KeyPairGerador parDeChaves DH
                    parDeChavesDH = new KeyPairDHGenerator(1024);
                    parDeChavesDH.createKeys();
                    byte[] publicKeyDHArray = parDeChavesDH.getPublicKey().getEncoded();
                    String publicKeyDH = Base64.getEncoder().encodeToString(publicKeyDHArray);
                    nomeCliente = cc.getName();

                    System.out.println("Nome: " + nomeCliente);
                    System.out.print("Deseja adicionar um username? (S/N): ");
                    //String escolha = sc.nextLine();
                    String escolha = scanner.nextLine();

                    if (escolha.equalsIgnoreCase("S")) {
                        System.out.print("Introduza o username: ");
                        username = scanner.nextLine();
                        usernameClientes.put(nomeCliente, username);
                    } else if (escolha.equalsIgnoreCase("N")) {
                    } else {
                        registar();
                    }
                    String s1 = "{\"command\":\"register\",\"src\":\"" + nomeCliente
                            + "\",\"remetente\":\"" + nomeCliente
                            + "\",\"remetenteUsername\":\"" + username
                            + "\",\"registoViaCC\":\"" + "true"
                            + "\",\"randomNumber\":\"" + randomNumber
                            + "\",\"publicKeyRSA\":\"" + publicKeyRSA
                            + "\",\"certificadoCC\":\"" + certificateCCString
                            + "\",\"publicKeyDH\":\"" + publicKeyDH + "\"}";

                    out.println(s1);

                    JsonReader jReader = new JsonReader(in);
                    JsonElement jElement = new JsonParser().parse(jReader);
                    JsonObject jObject = jElement.getAsJsonObject();

                    if (jObject.get("error").getAsString().equals("ok")) {
                        if (username.equals("Nao Definido")) {
                            System.out.println(">> O cliente " + nomeCliente + " foi registado com sucesso.");
                            System.out.println("");
                            limitDelimiter++;
                        } else {
                            System.out.println(">> O cliente " + nomeCliente + " (" + username + ")" + " foi registado com sucesso.");
                            System.out.println("");
                            limitDelimiter++;
                        }
                    } else {
                        System.out.println(">> Cliente já registado. Considere outro nome.");
                        System.out.println("");
                    }
                } else {
                    System.out.println("Função registar apenas disponivel 1 vez");
                }
                break;
            case 2:
                if (limitDelimiter == 1) {
                    //KeyPairGerador parDeChaves RSA
                    parDeChavesRSA = new KeyPairRSAGenerator(1024);
                    parDeChavesRSA.createKeys();
                    byte[] publicKeyRSAArray = parDeChavesRSA.getPublicKey().getEncoded();
                    String publicKeyRSA = Base64.getEncoder().encodeToString(publicKeyRSAArray);

                    //KeyPairGerador parDeChaves DH
                    parDeChavesDH = new KeyPairDHGenerator(1024);
                    parDeChavesDH.createKeys();
                    byte[] publicKeyDHArray = parDeChavesDH.getPublicKey().getEncoded();
                    String publicKeyDH = Base64.getEncoder().encodeToString(publicKeyDHArray);

                    System.out.print("Nome Cliente: ");
                    String nome = scanner.nextLine();
                    nomeCliente = nome;

                    String s1 = "{\"command\":\"register\",\"src\":\"" + nomeCliente
                            + "\",\"remetente\":\"" + nomeCliente
                            + "\",\"registoViaCC\":\"" + "false"
                            + "\",\"randomNumber\":\"" + randomNumber
                            + "\",\"publicKeyRSA\":\"" + publicKeyRSA
                            + "\",\"publicKeyDH\":\"" + publicKeyDH + "\"}";

                    out.println(s1);

                    JsonReader jReader = new JsonReader(in);
                    JsonElement jElement = new JsonParser().parse(jReader);
                    JsonObject jObject = jElement.getAsJsonObject();

                    if (jObject.get("error").getAsString().equals("ok")) {
                        System.out.println(">> O cliente " + nomeCliente + " foi registado com sucesso.");
                        System.out.println("");
                        limitDelimiter++;
                    } else {
                        System.out.println(">> Cliente já registado. Considere outro nome.");
                        System.out.println("");
                    }
                } else {
                    System.out.println("Função registar apenas disponivel 1 vez");
                }
                break;
        }
    }

    public static void sendSelections() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {
        int escolha;
        System.out.println("[1] Enviar a todos os utilizadores");
        System.out.println("[2] Encriptacao Simetrica");
        System.out.println("[3] Encriptacao Hibrida");
        System.out.println("[4] Acordo de chave de sessao usando uma senha");
        System.out.println("[5] Acordo de chave de sessao usando o algoritmo Diffie Helman");
        System.out.println("[6] Acordo de chave de sessao usando uma chave de sessao cifrada com a Publica do Interlocutor");
        System.out.print(">> Selecione o tipo de envio: ");

        escolha = sc.nextInt();
        System.out.println("");

        switch (escolha) {
            case 1:
                sendToAll();
                break;
            case 2:
                sendSimetricCipher();
                break;
            case 3:
                sendHybridCipher();
                break;
            case 4:
                sessionKeyPassword();
                break;
            case 5:
                sessionKeyDiffieHelman();
                break;
            case 6:
                sessionKeyPublicKey();
                break;
            default:
                System.out.println(">> Opcao Invalida, repita.");
                printSelections();
                break;
        }
    }

    public static void sendToAll() throws IOException {
        Scanner scanner = new Scanner(System.in);

        String code = "all";

        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();

        String s1 = "{\"command\":\"send\""
                + ",\"remetente\":\"" + nomeCliente
                + "\",\"msg\":\"" + msg
                + "\",\"code\":\"" + code
                + "\"}";

        out.println(s1);

        sendedMsg();
    }

    public static void sendSimetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception {
        Scanner scanner = new Scanner(System.in);

        byte[] saltArray = getSalt().getBytes();
        String salt = Base64.getEncoder().encodeToString(saltArray);

        String code = "DESede";

        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            System.out.print("Password: ");
            String pwdChat = scanner.nextLine();

            System.out.print("Mensagem: ");
            String msg = scanner.nextLine();

            byte[] msgToByteArray = msg.getBytes();
            String msgCifrada = Base64.getEncoder().encodeToString(DESede.encrypt(pwdChat, saltArray, msgToByteArray));

            String innerMsg = "{\"msgBody\":\"" + msgCifrada
                    + "\",\"salt\":\"" + salt
                    + "\"}";

            String toMAC = msgCifrada.concat(salt);

            String innerMsgMAC = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(toMAC, pwdChat));

            String outterMsg = "{\"command\":\"send\",\"dst\":\"" + dst
                    + "\",\"remetente\":\"" + nomeCliente
                    + "\",\"msg\":" + innerMsg
                    + ",\"ID\":\"" + code
                    + "\",\"HMAC\":\"" + innerMsgMAC + "\"}";

            out.println(outterMsg);

            sendedMsg();
        } else {
            System.out.println(" >> Cliente procurado não esta online");
            sendSimetricCipher();
        }
    }

    public static void sendHybridCipher() throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeySpecException, IOException, GeneralSecurityException, Exception {

        Scanner scanner = new Scanner(System.in);
        String code = "cifraHibrida";

        String publicKeyDestinatarioString = "";

        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result = resultArray.get(0).getAsJsonObject();
            publicKeyDestinatarioString = result.get("publicKeyRSA").getAsString();

        } else {
            System.out.println(" >> Cliente procurado não esta online");
            sendHybridCipher();
        }

        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();
        byte[] msgToByteArray = msg.getBytes();

        des = new DES();
        //1) Cifrar a mensagem com a chave simetrica
        byte[] msgCifradaBytes = des.cipherMsg(msgToByteArray);
        String msgCifradaString = Base64.getEncoder().encodeToString(msgCifradaBytes);

        //2) Assinar
        String assinatura = "";
        if (registoViaCC == false) {
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(parDeChavesRSA.getPrivateKey());
            sig.update(msgCifradaBytes);
            assinatura = Base64.getEncoder().encodeToString(sig.sign());
        } else {
            assinatura = cc.signMsg(msgCifradaBytes);
        }

        PublicKey publicKey = ConvertKeys.StringToPublicKeyRSA(publicKeyDestinatarioString);
        byte[] sk = des.getKey().getEncoded();

        String chaveSimetricaCifrada = Base64.getEncoder().encodeToString(CipherAssimetricKeys.cipher(publicKey, sk));

        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                + "\",\"remetente\":\"" + nomeCliente
                + "\",\"msg\":\"" + msgCifradaString
                + "\",\"ID\":\"" + code
                + "\",\"assinatura\":\"" + assinatura
                + "\",\"chave\":\"" + chaveSimetricaCifrada + "\"}";

        out.println(s1);

        sendedMsg();
    }

    public static void sessionKeyPassword() throws NoSuchAlgorithmException, SignatureException,
            InvalidKeyException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Scanner scanner = new Scanner(System.in);
        String randomNumberDestinatario = "";
        String code = "";

        System.out.print("Destinatario: ");
        String dst = scanner.nextLine();

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");
        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result = resultArray.get(0).getAsJsonObject();
            randomNumberDestinatario = result.get("randomNumber").getAsString();
        } else {
            System.out.println("Cliente não existe.");
            sessionKeyPassword();
        }

        System.out.println(">> 1 - Acordar chave de sessão");
        System.out.println(">> 2 - Enviar mensagens");
        System.out.print(">> Opcao: ");
        int op = scanner.nextInt();
        switch (op) {
            case 1:
                code = "acordoChavesPassword";
                if (limitDelimiter != 1 && !(clientKeysPassword.containsKey(dst))) {
                    System.out.print("Password: ");
                    scanner.nextLine();
                    String pwdChat = scanner.nextLine();

                    String toDigestString = pwdChat.concat(randomNumber).concat(randomNumberDestinatario);
                    byte[] toDigestArray = toDigestString.getBytes();

                    //MessageDigest md = MessageDigest.getInstance("MD5");
                    //md.update(toDigestArray);
                    MessageDigest md5 = MessageDigest.getInstance("MD5");
                    byte[] digest = md5.digest(toDigestArray);
                    digest = Arrays.copyOf(digest, 8);

                    //byte[] digest = md.digest();
                    String digestString = Base64.getEncoder().encodeToString(digest);

                    String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                            + "\",\"remetente\":\"" + nomeCliente
                            + "\",\"ID\":\"" + code
                            + "\",\"chaveSessao\":\"" + digestString + "\"}";

                    out.println(s1);
                    sendedKey();

                    HashMap<byte[], String> tmp = new HashMap<>();
                    tmp.put(digest, pwdChat);
                    //HashMap
                    if (!clientKeysPassword.containsKey(dst)) {
                        clientKeysPassword.put(dst, tmp);
                    }
                    limitDelimiter++;
                } else {
                    System.out.println("Chaves de sessão ja estabelecidas");
                    sessionKeyPassword();
                }
                break;
            case 2:
                code = "envioMsgPassword";
                if (clientKeysPassword.containsKey(dst)) {
                    System.out.print("Mensagem: ");
                    scanner.nextLine();
                    String msg = scanner.nextLine();
                    byte[] msgToByteArray = msg.getBytes();

                    //1) Cifrar a mensagem com a chave simetrica
                    des = new DES();

                    HashMap<byte[], String> tmp = clientKeysPassword.get(dst);
                    byte[] digest = null;
                    String pwdChat = null;

                    for (Map.Entry<byte[], String> entry : tmp.entrySet()) {
                        digest = entry.getKey();
                        pwdChat = entry.getValue();
                    }

                    byte[] msgCifradaBytes = des.cipherMsgGivenByteArraySecretKey(msgToByteArray, digest);
                    String msgCifradaString = Base64.getEncoder().encodeToString(msgCifradaBytes);

                    //2) Autenticar a msg
                    String msgMAC = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(msgCifradaString, pwdChat));

                    if (msg.equals("ENCERRAR")) {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"HMAC\":\"" + msgMAC + "\"}";
                        out.println(s1);
                        sendedMsg();
                        clientKeysPassword.remove(dst);
                        System.out.println("Acordo de chaves terminado!");
                    } else {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"HMAC\":\"" + msgMAC + "\"}";
                        out.println(s1);
                        sendedMsg();
                    }

                } else {
                    System.out.println("Chave de sessao nao definida para o utilizador pretendido");
                    sessionKeyPassword();
                }
                break;
        }
    }

    public static void sessionKeyDiffieHelman() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException,
            KeyStoreException, CertificateException, UnrecoverableKeyException {
        Scanner scanner = new Scanner(System.in);
        String publicKeyDstStringDH = "";
        String code = "";

        System.out.print("Destinatario: ");
        scanner.nextLine();
        String dst = scanner.nextLine();

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");
        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result = resultArray.get(0).getAsJsonObject();
            publicKeyDstStringDH = result.get("publicKeyDH").getAsString();
        } else {
            System.out.println("Cliente não existe.");
            sessionKeyDiffieHelman();
        }

        System.out.println(">> 1 - Acordar chave de sessão");
        System.out.println(">> 2 - Enviar mensagens");
        System.out.print(">> Opcao: ");
        int op = scanner.nextInt();
        switch (op) {
            case 1:
                code = "acordoChavesDH";
                if (limitDelimiter != 1 && !(clientKeysDH.containsKey(dst))) {
                    KeyAgreement ka;
                    ka = KeyAgreement.getInstance("DiffieHellman");
                    ka.init(parDeChavesDH.getPrivateKey());
                    PublicKey publicKeyDestinatarioDH = ConvertKeys.StringToPublicKeyDH(publicKeyDstStringDH);
                    ka.doPhase(publicKeyDestinatarioDH, true);
                    SecretKey secretKey = ka.generateSecret("DES");

                    String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                            + "\",\"remetente\":\"" + nomeCliente
                            + "\",\"ID\":\"" + code
                            + "\",\"chaveSessao\":\"" + secretKey + "\"}";

                    out.println(s1);
                    sendedKey();

                    //HashMap
                    if (!clientKeysDH.containsKey(dst)) {
                        clientKeysDH.put(dst, secretKey);
                    }
                    limitDelimiter++;
                } else {
                    System.out.println("Chaves de sessão ja estabelecidas");
                    sessionKeyDiffieHelman();
                }
                break;
            case 2:
                code = "envioMsgDH";
                if (clientKeysDH.containsKey(dst)) {
                    System.out.print("Mensagem: ");
                    scanner.nextLine();
                    String msg = scanner.nextLine();
                    byte[] msgToByteArray = msg.getBytes();

                    //1) Cifrar a mensagem com a chave simetrica
                    des = new DES();
                    byte[] msgCifradaBytes = des.cipherMsgGivenByteArraySecretKey(msgToByteArray, clientKeysDH.get(dst).getEncoded());
                    String msgCifradaString = Base64.getEncoder().encodeToString(msgCifradaBytes);

                    //2) Assinar
                    Signature sig = Signature.getInstance("SHA1WithRSA");
                    sig.initSign(parDeChavesRSA.getPrivateKey());
                    sig.update(msgCifradaBytes);
                    String assinatura = Base64.getEncoder().encodeToString(sig.sign());

                    if (msg.equals("ENCERRAR")) {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"assinatura\":\"" + assinatura + "\"}";
                        out.println(s1);
                        sendedMsg();
                        clientKeysDH.remove(dst);
                        System.out.println("Acordo de chaves terminado!");
                    } else {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"assinatura\":\"" + assinatura + "\"}";
                        out.println(s1);
                        sendedMsg();
                    }

                } else {
                    System.out.println("Chave de sessao nao definida para o utilizador pretendido");
                    sessionKeyDiffieHelman();
                }
                break;
        }
    }

    public static void sessionKeyPublicKey() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException,
            KeyStoreException, CertificateException, UnrecoverableKeyException {
        Scanner scanner = new Scanner(System.in);
        String publicKeyDstString = "";
        String code = "";

        System.out.print("Destinatario: ");
        String dst = scanner.nextLine();

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");
        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result = resultArray.get(0).getAsJsonObject();
            publicKeyDstString = result.get("publicKeyRSA").getAsString();
        } else {
            System.out.println("Cliente não existe.");
            sessionKeyPublicKey();
        }

        System.out.println(">> 1 - Acordar chave de sessão");
        System.out.println(">> 2 - Enviar mensagens");
        System.out.print(">> Opcao: ");
        int op = scanner.nextInt();
        switch (op) {
            case 1:
                code = "acordoChavesPublicKey";
                if (limitDelimiter != 1 && !(clientKeysPublicKey.containsKey(dst))) {
                    KeyGenerator kg = KeyGenerator.getInstance("DES");
                    kg.init(new SecureRandom());
                    SecretKey sk = kg.generateKey();

                    byte[] secretKeyBytes = sk.getEncoded();

                    PublicKey publicKeyDestinatario = ConvertKeys.StringToPublicKeyRSA(publicKeyDstString);
                    byte[] secretKeyBytesCifrado = CipherAssimetricKeys.cipher(publicKeyDestinatario, secretKeyBytes);
                    String secretKeyToSend = Base64.getEncoder().encodeToString(secretKeyBytesCifrado);

                    String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                            + "\",\"remetente\":\"" + nomeCliente
                            + "\",\"ID\":\"" + code
                            + "\",\"chaveSessao\":\"" + secretKeyToSend + "\"}";

                    out.println(s1);
                    sendedKey();

                    //HashMap
                    if (!clientKeysPublicKey.containsKey(dst)) {
                        clientKeysPublicKey.put(dst, sk);
                    }
                    limitDelimiter++;
                } else {
                    System.out.println("Chaves de sessão ja estabelecidas");
                    sessionKeyPublicKey();
                }
                break;
            case 2:
                code = "envioMsgPublicKey";
                if (clientKeysPublicKey.containsKey(dst)) {
                    System.out.print("Mensagem: ");
                    scanner.nextLine();
                    String msg = scanner.nextLine();
                    byte[] msgToByteArray = msg.getBytes();

                    //1) Cifrar a mensagem com a chave simetrica
                    des = new DES();
                    byte[] msgCifradaBytes = des.cipherMsgGivenByteArraySecretKey(msgToByteArray, clientKeysPublicKey.get(dst).getEncoded());
                    String msgCifradaString = Base64.getEncoder().encodeToString(msgCifradaBytes);

                    //2) Assinar
                    String assinatura = "";
                    if (registoViaCC == false) {
                        Signature sig = Signature.getInstance("SHA1WithRSA");
                        sig.initSign(parDeChavesRSA.getPrivateKey());
                        sig.update(msgCifradaBytes);
                        assinatura = Base64.getEncoder().encodeToString(sig.sign());
                    } else {
                        assinatura = cc.signMsg(msgCifradaBytes);
                    }

                    if (msg.equals("ENCERRAR")) {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"assinatura\":\"" + assinatura + "\"}";
                        out.println(s1);
                        sendedMsg();
                        clientKeysPublicKey.remove(dst);
                        System.out.println("Acordo de chaves terminado!");
                    } else {
                        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst
                                + "\",\"remetente\":\"" + nomeCliente
                                + "\",\"msg\":\"" + msgCifradaString
                                + "\",\"ID\":\"" + code
                                + "\",\"assinatura\":\"" + assinatura + "\"}";
                        out.println(s1);
                        sendedMsg();
                    }
                } else {
                    System.out.println("Chave de sessao nao definida para o utilizador pretendido");
                    sessionKeyPublicKey();
                }
                break;
        }
    }

    public static void printSelections() throws IOException, CertificateException {
        int escolha;
        System.out.println("[1] Listar todos os clientes");
        System.out.println("[2] Listar um cliente especifico");
        System.out.print(">> Selecione o tipo de consulta: ");

        escolha = sc.nextInt();

        switch (escolha) {
            case 1:
                printAllClients();
                break;
            case 2:
                printOneClient();
                break;
            default:
                System.out.println(">> Opcao Invalida, repita.");
                printSelections();
                break;
        }
    }

    public static void printAllClients() throws IOException, CertificateException {
        out.print("{\"command\":\"list\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            //Cliente que se quer enviar a mensagem EXISTE

            JsonArray resultArray = jObject.get("result").getAsJsonArray();

            for (int i = 0; i < resultArray.size(); i++) {
                JsonObject result2 = resultArray.get(i).getAsJsonObject();
                if (result2.get("registoViaCC").getAsString().equals("false")) {
                    String nomeDestinatario = result2.get("src").getAsString();
                    String publicKeyRSA = result2.get("publicKeyRSA").getAsString();
                    String publicKeyDH = result2.get("publicKeyDH").getAsString();
                    String randomNumber = result2.get("randomNumber").getAsString();

                    System.out.println(">> " + nomeDestinatario + ": online");
                    System.out.println("Chave Publica RSA: " + publicKeyRSA);
                    System.out.println("Chave Publica DH: " + publicKeyDH);
                    System.out.println("Valor Aleatorio: " + randomNumber);
                    System.out.println("");
                } else {
                    String nomeDestinatario = result2.get("src").getAsString();
                    String publicKeyRSA = result2.get("publicKeyRSA").getAsString();
                    String publicKeyDH = result2.get("publicKeyDH").getAsString();
                    String randomNumber = result2.get("randomNumber").getAsString();

                    String certificadoString = result2.get("certificadoCC").getAsString();
                    Certificate certificado = cc.getCertificateGivenString(certificadoString);
                    String publicKeyCC = cc.getPublicKeyStringGivenCertificate(certificado);

                    System.out.println(">> " + nomeDestinatario + ": online");
                    System.out.println("Chave Publica RSA: " + publicKeyRSA);
                    System.out.println("Chave Publica DH: " + publicKeyDH);
                    System.out.println("Chave Publica CC: " + publicKeyCC);
                    System.out.println("Valor Aleatorio: " + randomNumber);
                    
                    System.out.println("");
                }

            }
        } else {
            System.out.println("Sem clientes registados");
        }
    }

    public static void printOneClient() throws IOException, CertificateException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("   >> Nome: ");
        String cliente = scanner.nextLine();

        String nomeAProcurar = cliente;
        for (Map.Entry<String, String> entry : usernameClientes.entrySet()) {
            if (cliente.equals(entry.getValue())) {
                nomeAProcurar = entry.getKey();
            }
        }
        out.print("{\"command\":\"list\",\"id\":\"" + nomeAProcurar + "\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result2 = resultArray.get(0).getAsJsonObject();

            if (result2.get("registoViaCC").getAsString().equals("false")) {
                String nomeDestinatario = result2.get("src").getAsString();
                String publicKeyRSA = result2.get("publicKeyRSA").getAsString();
                String publicKeyDH = result2.get("publicKeyDH").getAsString();
                String randomNumber = result2.get("randomNumber").getAsString();

                System.out.println(">> " + nomeDestinatario + ": online");
                System.out.println("Chave Publica RSA: " + publicKeyRSA);
                System.out.println("Chave Publica DH: " + publicKeyDH);
                System.out.println("Valor Aleatorio: " + randomNumber);
            } else {
                String nomeDestinatario = result2.get("src").getAsString();
                String publicKeyRSA = result2.get("publicKeyRSA").getAsString();
                String publicKeyDH = result2.get("publicKeyDH").getAsString();
                String randomNumber = result2.get("randomNumber").getAsString();
                
                String certificadoString = result2.get("certificadoCC").getAsString();
                Certificate certificado = cc.getCertificateGivenString(certificadoString);
                String publicKeyCC = cc.getPublicKeyStringGivenCertificate(certificado);

                System.out.println(">> " + nomeDestinatario + ": online");
                System.out.println("Chave Publica RSA: " + publicKeyRSA);
                System.out.println("Chave Publica DH: " + publicKeyDH);
                System.out.println("Chave Publica CC: " + publicKeyCC);
                System.out.println("Valor Aleatorio: " + randomNumber);
            }

        } else {
            System.out.println(">> Cliente nao registado");
        }
    }

    public static String getSalt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return new String(salt);
    }

    public static String getSecureRandom() {
        SecureRandom ranGen = new SecureRandom();
        byte[] desKey = new byte[16];
        ranGen.nextBytes(desKey);
        return Base64.getEncoder().encodeToString(desKey);
    }

    public static void sendedMsg() throws IOException {
        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Mensagem Enviada");
        }
    }

    public static void sendedKey() throws IOException {
        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Chave de Sessao Estabelecida!");
        }
    }
}
