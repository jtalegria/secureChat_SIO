package chat;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SecureChat2 {

    // Classe cliente
    static Scanner sc = new Scanner(System.in);
    static Socket socket;
    static BufferedReader in;
    static InputStream inStream;
    static PrintStream out;
    static byte[] buffer = new byte[1024];
    static int l;
    static int registerLimit = 1;
    static KeyPairRSAGenerator parDeChavesRSA;
    static KeyPairDHGenerator parDeChavesDH;
    static DES des;

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
                    //l = inStream.read(buffer, 0, buffer.length);
                    //System.out.write(buffer, 0, l);
                    //System.out.print("\n");
                    
                    JsonReader jReader = new JsonReader(in);
                    JsonElement jElement = new JsonParser().parse(jReader);
                    JsonObject jObject = jElement.getAsJsonObject();

                    if (jObject.get("code").getAsString().equals("DESede")) {
                        //DECIFRAR DES
                        
                        System.out.println("\n>> Recebeu uma mensagem nova (Cifrada Simetricamente)!");
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
                            System.out.print(">> Mensagem: " + msgDecifrada);
                        } else {
                            System.out.println("MACs diferentes!");
                        }

                        break;
                    }
                    
                    else if(jObject.get("code").getAsString().equals("cifraHibrida")){
                        // DECIFRAR A CIFRA HIBRIDA
                        des = new DES();
                        System.out.println("\n>> Recebeu uma mensagem nova (Cifrada Hibrida)!");
                        
                        byte[] chaveSimetricaCifrada = Base64.getDecoder().decode(jObject.get("chave").getAsString());
                        byte[] msgToDecipher = Base64.getDecoder().decode(jObject.get("msg").getAsString());
                        
                        PrivateKey myPrivate = parDeChavesRSA.getPrivateKey();
                        
                        byte[] chaveSimetricaDecifrada = CipherAssimetricKeys.decrypt(myPrivate, chaveSimetricaCifrada);
                        
                        byte[] msgDecifradaArray = des.decipherMsgGivenSecretKey(msgToDecipher, chaveSimetricaDecifrada);
                        
                        String msgDecifrada = new String(msgDecifradaArray);
                        //String msgDecifrada = Base64.getEncoder().encodeToString(msgDecifradaArray);
                        
                        System.out.println(">> Mensagem: " + msgDecifrada);
                        break;
                    }
                    
                    else if(jObject.get("code").getAsString().equals("DiffieHelman  ")){
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
                //printClients();
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

    public static void registar() throws IOException, NoSuchAlgorithmException {
        //TODO criar par de chaves para cada novo cliente

        if (registerLimit == 1) {
            Scanner scanner = new Scanner(System.in);

            //KeyPairGerador parDeChaves RSA
            parDeChavesRSA = new KeyPairRSAGenerator(1024);
            parDeChavesRSA.createKeys();
            byte[] publicKeyRSAArray = parDeChavesRSA.getPublicKey().getEncoded();
            String publicKeyRSA = Base64.getEncoder().encodeToString(publicKeyRSAArray);

            //KeyPairGerador parDeChaves DH
            parDeChavesDH = new KeyPairDHGenerator(1024);
            parDeChavesDH.createKeys();
            byte[] publicKeyDHArray = parDeChavesDH.getPublicKey().getEncoded();
            String publicKeyDH = Base64.getEncoder().encodeToString(publicKeyRSAArray);
            
            
            System.out.print("Nome Cliente: ");
            String cliente = scanner.nextLine();

            String s1 = "{\"command\":\"register\",\"src\":\"" + cliente + "\",\"publicKeyRSA\":\"" + publicKeyRSA 
                    + "\",\"publicKeyDH\":\"" + publicKeyDH + "\"}";
            
            out.println(s1);

            JsonReader jReader = new JsonReader(in);
            JsonElement jElement = new JsonParser().parse(jReader);
            JsonObject jObject = jElement.getAsJsonObject();

            if (jObject.get("error").getAsString().equals("ok")) {
                System.out.println(">> O cliente " + cliente + " foi registado com sucesso.");
                System.out.println("");
                registerLimit++;
            } else {
                System.out.println(">> Cliente já registado. Considere outro nome.");
                System.out.println("");
            }
        } else {
            System.out.println("Função registar apenas disponivel 1 vez");
        }
    }

    public static void sendSelections() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {
        int escolha;
        System.out.println("[1] Enviar a todos os utilizadores");
        System.out.println("[2] Sem encriptacao para um cliente");
        System.out.println("[3] Encriptacao Simetrica");
        System.out.println("[4] Encriptacao Hibrida");
        System.out.println("[5] Encriptacao Diffie Helman");
        System.out.print(">> Selecione o tipo de envio: ");

        escolha = sc.nextInt();
        System.out.println("");

        switch (escolha) {
            case 1:
                sendToAll();
                break;
            case 2:
                sendNoCipher();
                break;
            case 3:
                sendSimetricCipher();
                break;
            case 4:
                sendHybridCipher();
                break;
            case 5:
                sendDiffieHelman();
                break;
            default:
                System.out.println(">> Opcao Invalida, repita.");
                printSelections();
                break;
        }
    }

    public static void sendToAll() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();

        //String s1 = "{\"command\":\"send\",\"dst\":\"" + dst + "\",\"msg\":\"" + msg + "\"}";
        String s1 = "{\"command\":\"send\", \"msg\":\"" + msg + "\"}";

        out.println(s1);

        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Mensagem Enviada");
        }
    }

    public static void sendNoCipher() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();

        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst + "\",\"msg\":\"" + msg + "\"}";

        out.println(s1);

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            System.out.println(">> Mensagem Enviada");
        }

//        if (in.readLine().equals("{\"error\":\"ok\"}")) {
//            System.out.println(">> Mensagem Enviada");
//        }
    }

//    public static void sendSimetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException,
//            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception {
//        Scanner scanner = new Scanner(System.in);
//
//        byte[] salt = getSalt().getBytes();
//        int keyLen = 192;  //24 bytes * 8 bits = 192 (tamanho da chave-bits)
//        String code = "DESede";
//
//        System.out.print("Enviar mensagem para: ");
//        String dst = scanner.nextLine();
//
//        System.out.print("Password: ");
//        String pwdChat = scanner.nextLine();
//
//        System.out.print("Mensagem: ");
//        String msg = scanner.nextLine();
//
//        byte[] msgToByteArray = msg.getBytes();
//
//        //byte[] chaveDerivada = KeyDerivation.deriveKey(pwdChat, salt, keyLen);
//        String msgCifrada = Base64.getEncoder().encodeToString(DESede.encrypt(pwdChat, salt, msgToByteArray));
//        String msgMAC = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(msg, pwdChat));
//
//        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst + "\",\"msg\":\"" + msgCifrada + "\",\"code\":\"" + code + "\""
//                + ",\"salt\":\"" + Base64.getEncoder().encodeToString(salt) + "\""
//                + ",\"HMAC\":\"" + msgMAC + "\"}";
//
//        out.println(s1);
//
//        if (in.readLine().equals("{\"error\":\"ok\"}")) {
//            System.out.println(">> Mensagem Enviada");
//        }
//    }
    
    public static void sendSimetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, Exception {
        Scanner scanner = new Scanner(System.in);

        byte[] saltArray = getSalt().getBytes();
        String salt = Base64.getEncoder().encodeToString(saltArray);
        
        String code = "DESede";
        
        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

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
        
        String mac = Base64.getEncoder().encodeToString(HMACsignature.calculateRFC2104HMAC(toMAC, pwdChat));
        
        String outterMsg = "{\"command\":\"send\",\"dst\":\"" + dst 
                + "\",\"msg\":" + innerMsg
                + ",\"code\":\"" + code
                + "\",\"HMAC\":\"" + mac + "\"}";
               
        
        System.out.println(outterMsg);

        out.println(outterMsg);
        
        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Mensagem Enviada");
        }
    }

    public static void sendHybridCipher() throws NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, 
            InvalidKeySpecException, IOException, GeneralSecurityException, Exception {
        
        Scanner scanner = new Scanner(System.in);
        String code = "cifraHibrida";
        
        String nomeDestinatario = "";
        String publicKeyDestinatarioString = "";
        
        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();
        byte[] msgToByteArray = msg.getBytes();

        des = new DES();
        //1) Cifrar a mensagem com a chave simetrica
        String msgCifrada = Base64.getEncoder().encodeToString(des.cipherMsg(msgToByteArray));

        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            //Cliente que se quer enviar a mensagem EXISTE

            JsonArray resultArray = jObject.get("result").getAsJsonArray();

            JsonObject result = resultArray.get(0).getAsJsonObject();

            nomeDestinatario = result.get("src").getAsString();
            publicKeyDestinatarioString = result.get("publicKeyRSA").getAsString();
//
//            if (nomeDestinatario.substring(6).equals(dst)) {
//                //Utilizador introduzido existe 
//                System.out.println("Somos iguais!");
//            }
        } 
        
        else {
            //Cliente que se quer enviar a mensagem NAO existe
        }
        
        PublicKey publicKey = ConvertKeys.StringToPublicKey(publicKeyDestinatarioString);
        byte[] sk = des.getKey().getEncoded();
        
        String chaveSimetricaCifrada = Base64.getEncoder().encodeToString(CipherAssimetricKeys.encrypt(publicKey, sk));
        
        String s1 = "{\"command\":\"send\",\"dst\":\"" + nomeDestinatario + "\",\"msg\":\"" + msgCifrada 
                + "\",\"code\":\"" + code
                + "\",\"chave\":\"" + chaveSimetricaCifrada + "\"}";

        out.println(s1);
        
        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Mensagem Enviada");
        }
    }

    public static void sendDiffieHelman() throws Exception{
        Scanner scanner = new Scanner(System.in);
        String code = "DiffieHelman";
        String nomeDestinatario = "";
        String publicKeyDestinatarioStringDH = "";
        
        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();
        
        out.println("{\"command\":\"list\",\"id\":\"" + dst + "\"}");

        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            //Cliente que se quer enviar a mensagem EXISTE
            
            JsonArray resultArray = jObject.get("result").getAsJsonArray();
            JsonObject result = resultArray.get(0).getAsJsonObject();

            nomeDestinatario = result.get("src").getAsString();
            publicKeyDestinatarioStringDH = result.get("publicKeyDH").getAsString();

        }
        else {
            System.out.println("Cliente não existe");
            sendDiffieHelman();
        }
        
        PublicKey publicKeyDestinatarioDH = ConvertKeys.StringToPublicKey(publicKeyDestinatarioStringDH);
        KeyAgreement ka;
        ka = KeyAgreement.getInstance("DH");
        ka.init(parDeChavesDH.getPrivateKey());
        ka.doPhase(publicKeyDestinatarioDH, true);
        
        SecretKey secretKey = ka.generateSecret("DES");
          
//        byte[] sk = des.getKey().getEncoded();
        
        
        
        //byte[] publicKeyDstDerivation = KeyDerivation.deriveKey(pwd, salt, )
    }
    
    public static void printClients() throws IOException {
        out.print("{\"command\":\"list\"}");
        ArrayList<String> tmpList = new ArrayList<String>();

        String serverMessage = in.readLine();

        if (serverMessage.equals("{\"error\":\"ok\",\"result\":[]}")) {
            System.out.println(">> Sem clientes registados");
        }

        String[] toParse = serverMessage.split(",");

        ArrayList<String> clientsList = new ArrayList<String>();
        clientsList = parseClients(toParse);

        System.out.println("Lista de clientes:");

        for (int i = 0; i < clientsList.size(); i++) {
            System.out.println(clientsList.get(i) + " - " + clientsList.get(i + 1));
            i++;
        }

        //System.out.println(clientsList);
    }

    public static void printSelections() throws IOException {
        int escolha;
        System.out.println("[1] Listar todos os clientes");
        System.out.println("[2] Listar um cliente especifico");
        System.out.print(">> Selecione o tipo de consulta: ");

        System.out.println("");
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

    public static void printAllClients() throws IOException {
        out.print("{\"command\":\"list\"}");
        
        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            //Cliente que se quer enviar a mensagem EXISTE

            JsonArray resultArray = jObject.get("result").getAsJsonArray();

            for (int i = 0; i < resultArray.size(); i++) {
                JsonObject result2 = resultArray.get(i).getAsJsonObject();
                String nomeDestinatario = result2.get("src").getAsString();
                String publicKey = result2.get("publicKey").getAsString();

                System.out.println(">> " + nomeDestinatario + ": online");
                System.out.println("Chave Publica " + publicKey);
                System.out.println("");
            }
        }
        else{
            System.out.println("Sem clientes registados");
        }
    }

    public static void printOneClient() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("   >> Nome: ");
        String cliente = scanner.nextLine();

        out.print("{\"command\":\"list\",\"id\":\"" + cliente + "\"}");
        
        JsonReader jReader = new JsonReader(in);
        JsonElement jElement = new JsonParser().parse(jReader);
        JsonObject jObject = jElement.getAsJsonObject();

        if (jObject.get("error").getAsString().equals("ok")) {
            //Cliente que se quer enviar a mensagem EXISTE

            JsonArray resultArray = jObject.get("result").getAsJsonArray();

            JsonObject result2 = resultArray.get(0).getAsJsonObject();

            String nomeDestinatario = result2.get("src").getAsString();
            String publicKey = result2.get("publicKey").getAsString();
            
            System.out.println(">> " + nomeDestinatario + ": online");
            System.out.println("Chave Publica: " + publicKey);
        }
        else{
            System.out.println(">> Cliente nao registado");
        }
    }

    public static ArrayList parseClients(String[] toParse) {
        ArrayList<String> tmpList = new ArrayList<String>();
        ArrayList<String> clientsList = new ArrayList<String>();
        ArrayList<String> clientsListInverted = new ArrayList<String>();

        for (int i = 1; i < toParse.length; i++) {
            if (toParse[i].startsWith("\"result\"")) {
                tmpList.add(toParse[i].substring(17));
            }

            if (toParse[i].startsWith("{\"src\"")) {
                tmpList.add(toParse[i].substring(7));
            }

            if (toParse[i].startsWith("\"id\"")) {
                tmpList.add(toParse[i].substring(5));
            }
        }

        for (int i = 0; i < tmpList.size(); i++) {
            String[] array = tmpList.get(i).split("\"");
            clientsList.add(array[1]);
        }

        for (int i = 0; i < clientsList.size(); i++) {
            clientsListInverted.add(clientsList.get(i + 1));
            clientsListInverted.add(clientsList.get(i));
            i++;
        }

        return clientsListInverted;
    }

    public static String getSalt() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return new String(salt);
    }
}
