import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * The AdHocChatNode class represents a node in the ad hoc chat network.
 * It provides functionality to send and receive encrypted messages between nodes using AES encryption.
 */
public class AdHocChatNode {
    private String username;
    private int port;
    private ServerSocket serverSocket;
    private SecretKeySpec secretKey;

    /**
     * Constructor to create an instance of AdHocChatNode.
     *
     * @param username   The username of the node.
     * @param port       The port number on which the node will listen for incoming messages.
     * @param passphrase The passphrase used to generate the AES encryption key.
     */
    public AdHocChatNode(String username, int port, String passphrase) {
        this.username = username;
        this.port = port;
        this.secretKey = generateSecretKey(passphrase);
    }

    /**
     * Generates a secret AES encryption key from the provided passphrase
     * using SHA-256 hashing algorithm.
     * @param passphrase The passphrase to be used for key generation.
     * @return The SecretKeySpec object representing the AES encryption key.
     */
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

    /**
     * Truncates the given key to the specified length.
     *
     * @param key    The key to be truncated.
     * @param length The length to which the key should be truncated.
     * @return The truncated key as a byte array.
     */
    private byte[] truncateKey(byte[] key, int length) {
        byte[] truncatedKey = new byte[length];
        System.arraycopy(key, 0, truncatedKey, 0, length);
        return truncatedKey;
    }

    /**
     * Encrypts the given message using the AES encryption algorithm with the
     * generated secret key.
     * @param message The message to be encrypted.
     * @return The encrypted message as a Base64 encoded string.
     */
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

    /**
     * Decrypts the given encrypted message using the AES encryption algorithm
     * with the generated secret key.
     * @param encryptedMessage The encrypted message
     *                         to be decrypted (Base64 encoded string).
     * @return The decrypted message as a plain text string.
     */
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

    /**
     * Starts the node by initializing the server socket to listen for incoming connections on the specified port.
     * It creates a new thread to handle incoming messages.
     *
     * @throws IOException If an I/O error occurs while starting the server socket.
     */
    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        new Thread(() -> acceptIncomingMessages()).start();
    }

    /**
     * Accepts incoming connections from other nodes and creates a new thread to handle each incoming message.
     */
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

    /**
     * Handles incoming messages from other nodes.
     * It reads the encrypted message from the input stream of the socket, decrypts it, and prints the decrypted message to the console.
     *
     * @param socket The socket representing the incoming connection.
     */
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

    /**
     * Sends the given message to multiple destination addresses and ports.
     * It encrypts the message using the AES encryption algorithm with the generated secret key
     * and sends the encrypted message to each destination using a separate socket connection.
     *
     * @param destAddresses The list of destination IP addresses.
     * @param destPorts     The list of destination port numbers.
     * @param message       The message to be sent.
     */
    public void sendMessage(List<String> destAddresses, List<Integer> destPorts, String message) {
        String encryptedMessage = encryptMessage(username + ": " + message);
        if (encryptedMessage != null) {
            for (int i = 0; i < destAddresses.size(); i++) {
                String ipAddress = destAddresses.get(i);
                int port = destPorts.get(i);
                try (Socket socket = new Socket(ipAddress, port);
                     PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
                    writer.println(encryptedMessage);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * The main method to run the AdHocChatNode application.
     * It prompts the user to enter the username, port number, and passphrase for the node.
     * Then, it creates a new AdHocChatNode instance with the provided information and starts the node.
     * It also allows the user to send messages to other nodes by entering destination IP addresses and port numbers.
     *
     * @param args Command-line arguments (not used in this application).
     * @throws IOException If an I/O error occurs during user input or starting the node.
     */
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

        List<String> destAddresses = new ArrayList<>();
        List<Integer> destPorts = new ArrayList<>();
        while (true) {
            System.out.print("> ");
            String message = bufferedReader.readLine();
            if (message.equalsIgnoreCase("exit")) {
                break;
            }
            System.out.print("Enter destination IP addresses (comma-separated): ");
            String[] ipAddresses = bufferedReader.readLine().split(",");
            System.out.print("Enter destination port numbers (comma-separated): ");
            String[] portNumbers = bufferedReader.readLine().split(",");
            destAddresses.clear();
            destPorts.clear();
            for (String ipAddress : ipAddresses) {
                destAddresses.add(ipAddress.trim());
            }
            for (String portStr : portNumbers) {
                destPorts.add(Integer.parseInt(portStr.trim()));
            }
            node.sendMessage(destAddresses, destPorts, message);
        }
    }
}
