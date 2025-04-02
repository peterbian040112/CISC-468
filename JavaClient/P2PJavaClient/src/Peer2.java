import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Scanner;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Peer2 {
    private static final String SERVICE_TYPE = "_p2pfileshare._tcp.local.";
    private static final String SERVICE_NAME = "JavaPeer2";
    private static final int PORT = 9001;
    private static final String SHARED_DIR = "JavaClient/P2PJavaClient/shared/";
    private static final String STORAGE_PASSWORD = "securepassword"; // In a real app, prompt the user
    private static final byte[] SALT = "p2p-storage-salt".getBytes();

    private KeyPair rsaKeyPair;
    private ServerSocket serverSocket;
    private JmDNS jmdns;
    private Gson gson;

    public Peer2() throws Exception {
        generateRSAKeys();
        this.gson = new GsonBuilder().create();
        startServer();
        registerService();
    }

    private void generateRSAKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
    }

    private String getLocalIp() throws SocketException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("10.255.255.255"), 1);
            return socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }

    private void registerService() throws IOException {
        jmdns = JmDNS.create(InetAddress.getLocalHost());
        ServiceInfo serviceInfo = ServiceInfo.create(SERVICE_TYPE, SERVICE_NAME, PORT, "version=1.0");
        jmdns.registerService(serviceInfo);
        System.out.println("[✓] Service '" + SERVICE_NAME + "' registered on " + getLocalIp() + ":" + PORT);
    }

    private List<Map<String, Object>> getSharedFiles() throws Exception {
        List<Map<String, Object>> files = new ArrayList<>();
        File sharedDir = new File(SHARED_DIR);
        if (!sharedDir.exists()) {
            sharedDir.mkdirs();
        }

        for (File file : sharedDir.listFiles()) {
            if (file.isFile()) {
                try {
                    byte[] data = readFileRaw(file.getName());
                    data = decryptWithPBKDF2(data);
                    String hash = computeHash(data);
                    Map<String, Object> fileInfo = new HashMap<>();
                    fileInfo.put("name", file.getName());
                    fileInfo.put("size", file.length());
                    fileInfo.put("hash", hash);
                    files.add(fileInfo);
                } catch (Exception e) {
                    System.out.println("[!] Failed to process file " + file.getName() + ": " + e.toString());
                }
            }
        }
        return files;
    }

    private void startServer() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("[*] Server listening on port " + PORT);
        new Thread(() -> {
            while (true) {
                try (Socket client = serverSocket.accept()) {
                    handleClient(client);
                } catch (Exception e) {
                    System.out.println("[!] Server error: " + e.getMessage());
                }
            }
        }).start();
    }

    private void handleClient(Socket client) throws Exception {
        System.out.println("[+] Connection from " + client.getInetAddress().getHostAddress());
        try (ObjectInputStream in = new ObjectInputStream(client.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(client.getOutputStream())) {

            String requestData = (String) in.readObject();
            Map<String, Object> request = gson.fromJson(requestData, Map.class);

            if ("key_exchange".equals(request.get("type"))) {
                System.out.println("[*] Received public key from client.");
                String peerPublicKeyPem = (String) request.get("public_key");
                PublicKey peerPublicKey = deserializePublicKey(peerPublicKeyPem);

                Map<String, String> response = new HashMap<>();
                response.put("type", "key_exchange_response");
                response.put("public_key", serializePublicKey(rsaKeyPair.getPublic()));
                out.writeObject(gson.toJson(response));
                out.flush();
                System.out.println("[✓] Sent back our public key.");
            } else if ("get_file_list".equals(request.get("type"))) {
                System.out.println("[*] Received file list request.");
                List<Map<String, Object>> files = getSharedFiles();
                Map<String, Object> response = new HashMap<>();
                response.put("type", "file_list");
                response.put("files", files);
                out.writeObject(gson.toJson(response));
                out.flush();
                System.out.println("[✓] " + files.size() + " file(s) found.");
            } else if ("file_request".equals(request.get("type"))) {
                String fname = (String) request.get("filename");
                System.out.println("[*] File requested: " + fname);

                Scanner scanner = new Scanner(System.in);
                System.out.print("[?] Allow peer to download file '" + fname + "'? (y/n): ");
                String userInput = scanner.nextLine().trim().toLowerCase();
                boolean allow = "y".equals(userInput);

                String sharedPath = SHARED_DIR + fname;
                if (allow && new File(sharedPath).exists()) {
                    byte[] encryptedData = readFileRaw(fname);
                    byte[] data = decryptWithPBKDF2(encryptedData);
                    String content = Base64.getEncoder().encodeToString(data);

                    Map<String, String> response = new HashMap<>();
                    response.put("type", "file_transfer");
                    response.put("filename", fname);
                    response.put("content", content);
                    out.writeObject(gson.toJson(response));
                    out.flush();
                    System.out.println("[✓] Sent file: " + fname);
                } else {
                    Map<String, String> response = new HashMap<>();
                    response.put("type", "refused");
                    out.writeObject(gson.toJson(response));
                    out.flush();
                    System.out.println("[!] Refused or not found: " + fname);
                }
            } else if ("send_file_request".equals(request.get("type"))) {
                String fname = (String) request.get("filename");
                String peerEcdhPubB64 = (String) request.get("ecdh_pub");
                String peerSignatureB64 = (String) request.get("signature");

                byte[] peerEcdhPub = Base64.getDecoder().decode(peerEcdhPubB64);
                byte[] peerSignature = Base64.getDecoder().decode(peerSignatureB64);

                String peerPublicKeyPem = (String) in.readObject();
                PublicKey peerPublicKey = deserializePublicKey(peerPublicKeyPem);

                if (!verifySignature(peerPublicKey, peerEcdhPub, peerSignature)) {
                    System.out.println("[!] Invalid RSA signature from sender.");
                    Map<String, String> response = new HashMap<>();
                    response.put("type", "refused");
                    response.put("reason", "bad_signature");
                    out.writeObject(gson.toJson(response));
                    out.flush();
                    return;
                }

                KeyPair ecdhKeyPair = generateECDHKeyPair();
                ECPublicKey localEcdhPub = (ECPublicKey) ecdhKeyPair.getPublic();
                ECPrivateKey localEcdhPriv = (ECPrivateKey) ecdhKeyPair.getPrivate();

                byte[] localEcdhPubBytes = localEcdhPub.getEncoded();
                byte[] localSignature = signData(rsaKeyPair.getPrivate(), localEcdhPubBytes);

                Map<String, String> response = new HashMap<>();
                response.put("type", "sts_response");
                response.put("ecdh_pub", Base64.getEncoder().encodeToString(localEcdhPubBytes));
                response.put("signature", Base64.getEncoder().encodeToString(localSignature));
                out.writeObject(gson.toJson(response));
                out.flush();

                String fileData = (String) in.readObject();
                Map<String, Object> filePayload = gson.fromJson(fileData, Map.class);

                if (!"file_transfer".equals(filePayload.get("type"))) {
                    System.out.println("[!] Expected file_transfer but got: " + filePayload.get("type"));
                    return;
                }

                String ciphertextB64 = (String) filePayload.get("content");
                String hashVal = (String) filePayload.get("hash");

                SecretKey aesKey = deriveSharedKey(localEcdhPriv, peerEcdhPub);
                byte[] plaintext = aesDecrypt(aesKey, ciphertextB64);
                String computedHash = computeHash(plaintext);

                if (!computedHash.equals(hashVal)) {
                    System.out.println("[!] Hash mismatch! Expected " + hashVal.substring(0, 8) + "..., got " + computedHash.substring(0, 8) + "...");
                    Map<String, String> response2 = new HashMap<>();
                    response2.put("type", "refused");
                    response2.put("reason", "hash_mismatch");
                    out.writeObject(gson.toJson(response2));
                    out.flush();
                    return;
                }

                System.out.print("[?] Accept file '" + fname + "' from peer? (y/n): ");
                String userInput2 = new Scanner(System.in).nextLine().trim().toLowerCase();
                if ("y".equals(userInput2)) {
                    new File("downloads_encrypted").mkdirs();
                    SecretKey storageKey = deriveKeyFromPassword(STORAGE_PASSWORD, SALT);
                    encryptAndStoreFile(plaintext, fname, storageKey);

                    System.out.println("[✓] File securely saved to downloads_encrypted/" + fname);
                    Map<String, String> response2 = new HashMap<>();
                    response2.put("type", "accept");
                    out.writeObject(gson.toJson(response2));
                    out.flush();
                } else {
                    Map<String, String> response2 = new HashMap<>();
                    response2.put("type", "refused");
                    out.writeObject(gson.toJson(response2));
                    out.flush();
                }
            }
        } catch (Exception e) {
            System.out.println("[!] Error handling request: " + e.toString());
            e.printStackTrace();
        }
    }

    private String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private PublicKey deserializePublicKey(String pem) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    private byte[] signData(PrivateKey privateKey, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    private boolean verifySignature(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private SecretKey deriveSharedKey(ECPrivateKey privateKey, byte[] peerPublicKeyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(peerPublicKeyBytes);
        ECPublicKey peerPublicKey = (ECPublicKey) kf.generatePublic(spec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(peerPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(sharedSecret);
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] aesDecrypt(SecretKey aesKey, String ciphertextB64) throws Exception {
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextB64);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(ciphertext);
    }

    private String computeHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        int iterations = 100000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private byte[] encryptWithPBKDF2(byte[] data) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKey key = deriveKeyFromPassword(STORAGE_PASSWORD, salt);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(salt);
        outputStream.write(encryptedData);
        return outputStream.toByteArray();
    }

    private byte[] decryptWithPBKDF2(byte[] encryptedData) throws Exception {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedData);
        byte[] salt = new byte[16];
        inputStream.read(salt);
        byte[] encryptedContent = new byte[encryptedData.length - 16];
        inputStream.read(encryptedContent);

        SecretKey key = deriveKeyFromPassword(STORAGE_PASSWORD, salt);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedContent);
    }

    private void encryptAndStoreFile(byte[] data, String fname, SecretKey storageKey) throws Exception {
        byte[] encryptedData = encryptWithPBKDF2(data);
        File file = new File("downloads_encrypted/" + fname);
        file.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(encryptedData);
        }
    }

    private void encryptAndStoreFileForSharing(String inputFilePath, String fname) throws Exception {
        // Read the raw file content
        File inputFile = new File(inputFilePath);
        byte[] data;
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            data = new byte[(int) inputFile.length()];
            fis.read(data);
        }

        // Encrypt the content
        byte[] encryptedData = encryptWithPBKDF2(data);

        // Store the encrypted file in the shared/ directory
        File sharedDir = new File(SHARED_DIR);
        if (!sharedDir.exists()) {
            sharedDir.mkdirs();
        }
        File outputFile = new File(SHARED_DIR + fname);
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(encryptedData);
        }
        System.out.println("[✓] Encrypted and stored file: " + fname);
    }

    private byte[] readFileRaw(String fname) throws IOException {
        File file = new File(SHARED_DIR + fname);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }

    public static void main(String[] args) throws Exception {
        Peer2 peer = new Peer2();
        // Encrypt a test file before starting the server
        peer.encryptAndStoreFileForSharing("JavaClient/P2PJavaClient/testFile/test.txt", "test.txt");
        System.out.println("[*] Peer running. Press Ctrl+C to exit.");
        try {
            while (true) {
                Thread.sleep(1000);
            }
        } catch (InterruptedException e) {
            System.out.println("\n[!] Shutting down...");
            peer.jmdns.close();
        }
    }
}