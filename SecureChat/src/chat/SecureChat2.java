package chat;


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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
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
    
    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException, 
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
                    l = inStream.read(buffer, 0, buffer.length);
                    System.out.write(buffer, 0, l);
                    System.out.print("\n");
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
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        
        KeyPair pair = keyGen.generateKeyPair();
        
        PrivateKey priv = pair.getPrivate();
        PublicKey pub = pair.getPublic();
        
        
        if (registerLimit == 1) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Nome Cliente: ");
            String cliente = scanner.nextLine();

            String s1 = "{\"command\":\"register\",\"src\":\"" + cliente + "\"}";
            out.println(s1);

            JsonReader jReader = new JsonReader(in);
            JsonElement jElement = new JsonParser().parse(jReader);
            JsonObject jObject = jElement.getAsJsonObject();

            if (jObject.get("error").getAsString().equals("ok")) {
                System.out.println(">> O cliente " + cliente + " foi registado com sucesso.");
                System.out.println("");
            } //        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            //            System.out.println(">> O cliente " + cliente + " foi registado com sucesso.");
            //            System.out.println("");
            //        } 
            else {
                System.out.println(">> Cliente já registado. Considere outro nome.");
                System.out.println("");
            }
            registerLimit++;
        }
        else{
            System.out.println("Função registar apenas disponivel 1 vez");
        }
    }

    public static void sendSelections() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int escolha;
        System.out.println("[1] Enviar a todos os utilizadores");
        System.out.println("[2] Sem encriptacao para um cliente");
        System.out.println("[3] Encriptacao Simetrica");
        System.out.print(">> Selecione o tipo de envio:");

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

    public static void sendNoCipher() throws IOException{
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
        
        if(jObject.get("error").getAsString().equals("ok")){
            System.out.println(">> Mensagem Enviada");
        }
        
//        if (in.readLine().equals("{\"error\":\"ok\"}")) {
//            System.out.println(">> Mensagem Enviada");
//        }
    }
    
    public static void sendSimetricCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException{
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enviar mensagem para: ");
        String dst = scanner.nextLine();

        System.out.print("Mensagem: ");
        String msg = scanner.nextLine();
        
        byte[] msgToByteArray = msg.getBytes();
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey sk = kg.generateKey();
        
        byte[] textoCifradoArray = CipherDES.cypherMsg(msgToByteArray, sk);
        String textoCifradoString = Base64.getEncoder().encodeToString(textoCifradoArray);
        
        //String s1 = "{\"command\":\"send\",\"dst\":\"" + dst + "\",\"msg\":\"" + msg + "\",\"code\":\"" + code + "\"}";

        String s1 = "{\"command\":\"send\",\"dst\":\"" + dst + "\",\"msg\":\"" + textoCifradoString + "\"}";
        out.println(s1);
        
        if (in.readLine().equals("{\"error\":\"ok\"}")) {
            System.out.println(">> Mensagem Enviada");
        }
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
        System.out.print(">> Selecione o tipo de consulta:");

        escolha = sc.nextInt();
        System.out.println("");

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
        String serverMessage = in.readLine();

        if (serverMessage.equals("{\"error\":\"ok\",\"result\":[]}")) {
            System.out.println(">> Sem clientes registados");
        }
        System.out.println(serverMessage);
    }

    public static void printOneClient() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.print(">> Nome: ");
        String cliente = scanner.nextLine();

        out.print("{\"command\":\"list\",\"id\":\"" + cliente + "\"}");
        String serverMessage = in.readLine();

        if (serverMessage.equals("{\"error\":\"ok\",\"result\":[]}")) {
            System.out.println(">> Sem clientes registados");
        }
        System.out.println(serverMessage);
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

}