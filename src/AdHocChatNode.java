import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;


public class AdHocChatNode {
    private String username;
    private int port;
    private ServerSocket serverSocket;
    private SecretKeySpec secretKey;

    public AdHocChatNode(String username, int port, String passphrase) {
        this.username = username;
        this.port = port;
        this.secretKey = generateSecretKey(passphrase);
    }

    private SecretKeySpec generateSecretKey(String passphrase) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(passphrase.getBytes(StandardCharsets.UTF_8));
            keyBytes = truncateKey(keyBytes, 16); // Use only the first 16 bytes for 128-bit AES key
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] truncateKey(byte[] key, int length) {
        byte[] truncatedKey = new byte[length];
        System.arraycopy(key, 0, truncatedKey, 0, length);
        return truncatedKey;
    }

    private String encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String decryptMessage(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        new Thread(() -> acceptIncomingMessages()).start();
    }

    private void acceptIncomingMessages() {
        try {
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> handleIncomingMessage(socket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleIncomingMessage(Socket socket) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            String message;
            while ((message = reader.readLine()) != null) {
                String decryptedMessage = decryptMessage(message);
                if (decryptedMessage != null) {
                    System.out.println(decryptedMessage);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(List<Integer> destPorts, String message) {
        String encryptedMessage = encryptMessage(username + ": " + message);
        if (encryptedMessage != null) {
            for (int port : destPorts) {
                try (Socket socket = new Socket("localhost", port);
                     PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
                    writer.println(encryptedMessage);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter your username: ");
        String username = bufferedReader.readLine();
        System.out.print("Enter the port number for this node: ");
        int port = Integer.parseInt(bufferedReader.readLine());
        System.out.print("Enter the passphrase: ");
        String passphrase = bufferedReader.readLine();

        AdHocChatNode node = new AdHocChatNode(username, port, passphrase);
        node.start();

        List<Integer> destPorts = new ArrayList<>();
        while (true) {
            System.out.print("> ");
            String message = bufferedReader.readLine();
            if (message.equalsIgnoreCase("exit")) {
                break;
            }
            System.out.print("Enter destination port numbers (comma-separated): ");
            String[] portNumbers = bufferedReader.readLine().split(",");
            destPorts.clear();
            for (String portStr : portNumbers) {
                destPorts.add(Integer.parseInt(portStr.trim()));
            }
            node.sendMessage(destPorts, message);
        }
    }
}
