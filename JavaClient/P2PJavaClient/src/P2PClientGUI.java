import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;
import javax.jmdns.ServiceInfo;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class P2PClientGUI {
    private JFrame frame;
    private JList<String> peerList;
    private JList<String> fileList;
    private JTextArea logArea;
    private DefaultListModel<String> peerModel;
    private DefaultListModel<String> fileModel;
    private KeyPair rsaKeyPair;
    private PublicKey peerPublicKey;
    private JmDNS jmdns;
    private String localPeerId;
    private String connectedPeerIp;
    private int connectedPeerPort;
    private Gson gson;
    private static final String SERVICE_TYPE = "_p2pfileshare._tcp.local.";
    private static final String SERVICE_NAME = "JavaClient";
    private static final int PORT = 25506;
    private static final String STORAGE_PASSWORD = "securepassword"; // In a real app, prompt the user
    private static final byte[] SALT = "p2p-storage-salt".getBytes();
    private SecretKey storageKey;
    private Map<String, String> trustedPeers; // Peer ID -> Public Key (simulated trust store)

    public P2PClientGUI() throws Exception {
        generateRSAKeys();
        this.gson = new GsonBuilder().create();
        this.trustedPeers = new HashMap<>();
        loadTrustedPeers();
        this.storageKey = deriveKeyFromPassword(STORAGE_PASSWORD, SALT);
        initializeGUI();
        startServer();
        registerService();
        startDiscovery();
    }

    private void generateRSAKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
    }

    private void initializeGUI() {
        frame = new JFrame("P2P Secure File Sharing (Java Client)");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.setSize(1000, 700); // Ensure the frame is large enough

        // Top Toolbar for global actions
        JToolBar toolbar = new JToolBar();
        JButton regenerateKeyButton = new JButton("Regenerate RSA Key");
        toolbar.add(regenerateKeyButton);
        toolbar.setFloatable(false); // Prevent toolbar from being dragged
        frame.add(toolbar, BorderLayout.NORTH);

        // Main content panel with peers, buttons, and files
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Peer Panel (Left)
        JPanel peerPanel = new JPanel(new BorderLayout());
        peerModel = new DefaultListModel<>();
        peerList = new JList<>(peerModel);
        peerList.setPreferredSize(new Dimension(300, 400)); // Widen the peer list
        peerPanel.add(new JScrollPane(peerList), BorderLayout.CENTER);
        peerPanel.setBorder(BorderFactory.createTitledBorder("Peers"));
        mainPanel.add(peerPanel, BorderLayout.WEST);

        // Center Button Panel with GridBagLayout to prevent overlap
        JPanel buttonPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10); // Add padding between buttons
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;

        JButton refreshButton = new JButton("Refresh Peers");
        JButton connectButton = new JButton("Connect to Selected Peer");
        JButton sendFileButton = new JButton("Send File to Selected Peer");
        JButton requestButton = new JButton("Request Selected Files");

        // Set maximum sizes to prevent buttons from growing too large
        Dimension buttonSize = new Dimension(200, 30);
        refreshButton.setMaximumSize(buttonSize);
        connectButton.setMaximumSize(buttonSize);
        sendFileButton.setMaximumSize(buttonSize);
        requestButton.setMaximumSize(buttonSize);

        gbc.gridy = 0;
        buttonPanel.add(refreshButton, gbc);
        gbc.gridy = 1;
        buttonPanel.add(connectButton, gbc);
        gbc.gridy = 2;
        buttonPanel.add(sendFileButton, gbc);
        gbc.gridy = 3;
        buttonPanel.add(requestButton, gbc);

        mainPanel.add(buttonPanel, BorderLayout.CENTER);

        // File Panel (Right)
        JPanel filePanel = new JPanel(new BorderLayout());
        fileModel = new DefaultListModel<>();
        fileList = new JList<>(fileModel);
        fileList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        fileList.setPreferredSize(new Dimension(300, 400)); // Widen the file list
        filePanel.add(new JScrollPane(fileList), BorderLayout.CENTER);
        filePanel.setBorder(BorderFactory.createTitledBorder("Shared Files"));
        mainPanel.add(filePanel, BorderLayout.EAST);

        // Add the main panel to the frame
        frame.add(mainPanel, BorderLayout.CENTER);

        // Log Panel (Bottom)
        logArea = new JTextArea(10, 70);
        logArea.setEditable(false);
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Log"));
        logScroll.setPreferredSize(new Dimension(1000, 200)); // Increase log area height
        frame.add(logScroll, BorderLayout.SOUTH);

        // Event Listeners
        refreshButton.addActionListener(e -> refreshPeers());
        connectButton.addActionListener(e -> connectToPeer());
        requestButton.addActionListener(e -> requestFiles());
        sendFileButton.addActionListener(e -> sendFileToPeer());
        regenerateKeyButton.addActionListener(e -> regenerateKeys());

        frame.setVisible(true);
    }

    private void startServer() throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        localPeerId = InetAddress.getLocalHost().getHostName() + ":" + serverSocket.getLocalPort();
        new Thread(() -> {
            while (true) {
                try (Socket client = serverSocket.accept()) {
                    // Handle incoming requests if needed
                } catch (Exception e) {
                    log("Server error: " + e.getMessage());
                }
            }
        }).start();
        log("Server started on " + localPeerId);
    }

    private void registerService() throws IOException {
        jmdns = JmDNS.create(InetAddress.getLocalHost());
        ServiceInfo serviceInfo = ServiceInfo.create(SERVICE_TYPE, SERVICE_NAME, PORT, "version=1.0");
        jmdns.registerService(serviceInfo);
        log("Registered mDNS service: " + localPeerId);
    }

    private void startDiscovery() {
        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            @Override
            public void serviceAdded(ServiceEvent event) {
                log("Service added: " + event.getName());
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                String peer = event.getName() + " - " + event.getInfo().getHostAddresses()[0] + ":" + event.getInfo().getPort();
                if (!peer.equals(localPeerId) && !peerModel.contains(peer)) {
                    peerModel.addElement(peer);
                    log("Discovered peer: " + peer);
                }
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                String peer = event.getName() + " - " + event.getInfo().getHostAddresses()[0] + ":" + event.getInfo().getPort();
                peerModel.removeElement(peer);
                log("Peer removed: " + peer);
            }
        });
    }

    private void refreshPeers() {
        peerModel.clear();
        log("Refreshing peer list...");
    }

    private void connectToPeer() {
        String selectedPeer = peerList.getSelectedValue();
        if (selectedPeer == null) {
            JOptionPane.showMessageDialog(frame, "Please select a peer.", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] parts = selectedPeer.split(" - ")[1].split(":");
        String ip = parts[0];
        int port = Integer.parseInt(parts[1]);

        try (Socket socket = new Socket()) {
            // Set a timeout to avoid hanging
            socket.connect(new InetSocketAddress(ip, port), 5000); // 5-second timeout
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            Map<String, String> msg = new HashMap<>();
            msg.put("type", "key_exchange");
            msg.put("public_key", serializePublicKey(rsaKeyPair.getPublic()));
            out.writeObject(gson.toJson(msg));
            out.flush();

            String data;
            try {
                data = (String) in.readObject();
            } catch (EOFException e) {
                log("Connection failed: Peer closed the connection unexpectedly");
                return;
            }

            Map<String, String> response = gson.fromJson(data, Map.class);
            if (!response.containsKey("public_key")) {
                log("Connection failed: Invalid response from peer");
                return;
            }
            String peerPubKey = response.get("public_key");
            peerPublicKey = deserializePublicKey(peerPubKey);

            String peerId = selectedPeer.split(" - ")[0].trim();
            if (!verifyPeerIdentity(peerId, peerPubKey)) {
                log("[!] Peer '" + peerId + "' fingerprint mismatch or untrusted.");
                JOptionPane.showMessageDialog(frame, "Could not verify peer identity: " + peerId, "Security Alert", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try (Socket socket2 = new Socket()) {
                socket2.connect(new InetSocketAddress(ip, port), 5000);
                ObjectOutputStream out2 = new ObjectOutputStream(socket2.getOutputStream());
                ObjectInputStream in2 = new ObjectInputStream(socket2.getInputStream());

                Map<String, String> request = new HashMap<>();
                request.put("type", "get_file_list");
                out2.writeObject(gson.toJson(request));
                out2.flush();

                String responseData;
                try {
                    responseData = (String) in2.readObject();
                } catch (EOFException e) {
                    log("Connection failed: Peer closed the connection unexpectedly while fetching file list");
                    return;
                }

                Map<String, Object> fileResponse = gson.fromJson(responseData, Map.class);
                if ("file_list".equals(fileResponse.get("type"))) {
                    fileModel.clear();
                    java.util.List<Map<String, Object>> files = (java.util.List<Map<String, Object>>) fileResponse.get("files");
                    for (Map<String, Object> file : files) {
                        String display = file.get("name") + " (" + file.get("size") + "B)";
                        fileModel.addElement(display);
                    }
                    log("Connected to " + ip + ":" + port + " to request file list.");
                } else {
                    log("Failed to receive file list.");
                }
            }

            connectedPeerIp = ip;
            connectedPeerPort = port;
        } catch (Exception e) {
            log("Connection failed: " + e.toString());
            e.printStackTrace();
        }
    }

    private void requestFiles() {
        if (connectedPeerIp == null || connectedPeerPort == 0) {
            JOptionPane.showMessageDialog(frame, "Please connect to a peer first.", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int[] selectedIndices = fileList.getSelectedIndices();
        if (selectedIndices.length == 0) {
            JOptionPane.showMessageDialog(frame, "Please select files to request.", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        new File("JavaDownload_encrypted").mkdirs();

        for (int index : selectedIndices) {
            String fname = fileModel.get(index).split(" \\(")[0];
            try (Socket socket = new Socket(connectedPeerIp, connectedPeerPort)) {
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                Map<String, String> request = new HashMap<>();
                request.put("type", "file_request");
                request.put("filename", fname);
                out.writeObject(gson.toJson(request));
                out.flush();

                String data = (String) in.readObject();
                Map<String, String> response = gson.fromJson(data, Map.class);

                if ("file_transfer".equals(response.get("type"))) {
                    byte[] fileData = Base64.getDecoder().decode(response.get("content"));
                    encryptAndStoreFile(fileData, fname, storageKey);
                    log("Downloaded: " + fname + " (" + fileData.length + " bytes)");
                } else if ("refused".equals(response.get("type"))) {
                    log("Refused by peer: " + fname);
                } else {
                    log("Unexpected response for " + fname);
                }
            } catch (Exception e) {
                log("[!] Error requesting " + fname + ": " + e.getMessage());
            }
        }
    }

    private void sendFileToPeer() {
        if (connectedPeerIp == null || connectedPeerPort == 0) {
            JOptionPane.showMessageDialog(frame, "Please connect to a peer first.", "Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(frame) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        String filename = file.getName();

        try (Socket socket = new Socket(connectedPeerIp, connectedPeerPort)) {
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            KeyPair ecdhKeyPair = generateECDHKeyPair();
            ECPublicKey ecdhPub = (ECPublicKey) ecdhKeyPair.getPublic();
            ECPrivateKey ecdhPriv = (ECPrivateKey) ecdhKeyPair.getPrivate();

            byte[] ecdhPubBytes = ecdhPub.getEncoded();
            byte[] ecdhSignature = signData(rsaKeyPair.getPrivate(), ecdhPubBytes);

            Map<String, String> request = new HashMap<>();
            request.put("type", "send_file_request");
            request.put("filename", filename);
            request.put("ecdh_pub", Base64.getEncoder().encodeToString(ecdhPubBytes));
            request.put("signature", Base64.getEncoder().encodeToString(ecdhSignature));
            out.writeObject(gson.toJson(request));
            out.flush();

            out.writeObject(serializePublicKey(rsaKeyPair.getPublic()));
            out.flush();

            String responseData = (String) in.readObject();
            Map<String, String> reply = gson.fromJson(responseData, Map.class);

            if (!"sts_response".equals(reply.get("type"))) {
                log("[!] Unexpected reply during STS handshake.");
                return;
            }

            byte[] peerEcdhPub = Base64.getDecoder().decode(reply.get("ecdh_pub"));
            byte[] peerSignature = Base64.getDecoder().decode(reply.get("signature"));

            if (!verifySignature(peerPublicKey, peerEcdhPub, peerSignature)) {
                log("[!] Invalid STS signature from peer.");
                return;
            }

            SecretKey aesKey = deriveSharedKey(ecdhPriv, peerEcdhPub);
            log("[✓] AES session key derived successfully.");

            byte[] data;
            try (FileInputStream fis = new FileInputStream(file)) {
                data = new byte[(int) file.length()];
                fis.read(data);
            }

            String ciphertextB64 = aesEncrypt(aesKey, data);
            String sha256 = computeHash(data);

            Map<String, String> filePayload = new HashMap<>();
            filePayload.put("type", "file_transfer");
            filePayload.put("filename", filename);
            filePayload.put("content", ciphertextB64);
            filePayload.put("hash", sha256);
            out.writeObject(gson.toJson(filePayload));
            out.flush();

            String response = (String) in.readObject();
            Map<String, String> reply2 = gson.fromJson(response, Map.class);

            if ("accept".equals(reply2.get("type"))) {
                log("[✓] Peer accepted the file '" + filename + "'.");
            } else if ("refused".equals(reply2.get("type"))) {
                String reason = reply2.getOrDefault("reason", "peer declined");
                log("[!] Peer refused the file '" + filename + "'. Reason: " + reason);
            } else {
                log("[!] Unexpected response after file sent: " + reply2);
            }
        } catch (Exception e) {
            log("[!] Failed to send file: " + e.getMessage());
        }
    }

    private void regenerateKeys() {
        if (JOptionPane.showConfirmDialog(frame, "Are you sure you want to regenerate your RSA key? This will invalidate your current identity.", "Confirm", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            try {
                generateRSAKeys();
                trustedPeers.clear();
                saveTrustedPeers();
                JOptionPane.showMessageDialog(frame, "New RSA key pair generated.", "Success", JOptionPane.INFORMATION_MESSAGE);
                log("[✓] Generated new RSA key pair.");
                log("[!] Old trusted peers removed due to key change.");
            } catch (Exception e) {
                log("[!] Failed to regenerate keys: " + e.getMessage());
            }
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

    private String aesEncrypt(SecretKey aesKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
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

    private void encryptAndStoreFile(byte[] data, String fname, SecretKey storageKey) throws Exception {
        byte[] encryptedData = encryptWithPBKDF2(data);
        File file = new File("JavaDownload_encrypted/" + fname);
        file.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(encryptedData);
        }
    }

    private boolean verifyPeerIdentity(String peerId, String publicKey) {
        String storedKey = trustedPeers.get(peerId);
        if (storedKey != null) {
            return storedKey.equals(publicKey);
        }

        String fingerprint;
        try {
            fingerprint = computeHash(publicKey.getBytes());
        } catch (NoSuchAlgorithmException e) {
            log("Failed to compute fingerprint: " + e.getMessage());
            JOptionPane.showMessageDialog(frame, "Cannot compute peer fingerprint due to missing SHA-256 algorithm.", "Security Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        int result = JOptionPane.showConfirmDialog(frame, "New peer '" + peerId + "'\nFingerprint:\n" + fingerprint.substring(0, 32) + "...\nTrust this peer?", "Untrusted Peer", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            trustedPeers.put(peerId, publicKey);
            saveTrustedPeers();
            return true;
        }
        return false;
    }

    private void loadTrustedPeers() {
        File file = new File("trusted_peers.json");
        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                trustedPeers = gson.fromJson(reader, Map.class);
            } catch (Exception e) {
                log("Failed to load trusted peers: " + e.getMessage());
            }
        }
    }

    private void saveTrustedPeers() {
        try (FileWriter writer = new FileWriter("trusted_peers.json")) {
            gson.toJson(trustedPeers, writer);
        } catch (Exception e) {
            log("Failed to save trusted peers: " + e.getMessage());
        }
    }

    private void log(String message) {
        logArea.append("> " + message + "\n");
    }

    public static void main(String[] args) throws Exception {
        new P2PClientGUI();
    }
}