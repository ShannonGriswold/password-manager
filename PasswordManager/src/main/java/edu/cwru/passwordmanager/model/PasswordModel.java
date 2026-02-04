package edu.cwru.passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.StringTokenizer;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    // !!! DO NOT CHANGE - VERY IMPORTANT FOR GRADING !!!
    static private File passwordFile = new File("passwords.txt");

    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    // TODO: You can set this to whatever you like to verify that the password the user entered is correct
    private static String verifyString = "Awoooo!";

    private void loadPasswords() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // TODO: Replace with loading passwords from file, you will want to add them to the passwords list defined above
        // TODO: Tips: Use buffered reader, make sure you split on separator, make sure you decrypt password
        BufferedReader reader = new BufferedReader(new FileReader(passwordFile));
        
        //Ignore the first line with the salt and encrypted token
        reader.readLine();

        while(reader.ready()) {
            String line = reader.readLine();
            StringTokenizer tokenizer = new StringTokenizer(line, separator);
            String label = tokenizer.nextToken();
            String decrypted = decryptPassword(tokenizer.nextToken());
            Password newPassword = new Password(label, decrypted);
            passwords.add(newPassword);
        }
        reader.close();
    }

    public PasswordModel() {
        try {
            loadPasswords();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        passwordFile.createNewFile();

        // TODO: Use password to create token and save in file with salt (TIP: Save these just like you would save password)
        generateSalt();
        passwordFilePassword = password;
        generateKey();

        saveFile(new ArrayList<>());
    }

    static public boolean verifyPassword(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        passwordFilePassword = password; // DO NOT CHANGE

        // TODO: Check first line and use salt to verify that you can decrypt the token using the password from the user
        // TODO: TIP !!! If you get an exception trying to decrypt, that also means they have the wrong passcode, return false!
        BufferedReader reader = new BufferedReader(new FileReader(passwordFile));
        StringTokenizer tokenizer = new StringTokenizer(reader.readLine(), separator);
        reader.close();

        passwordFileSalt = tokenizer.nextToken().getBytes();
        generateKey();
        String encryptedToken = tokenizer.nextToken();

        String decryptResult = null;
        try {
            decryptResult = decryptPassword(encryptedToken);
        } catch (Exception e) {
            return false;
        }

        if(verifyString.equals(decryptResult)) {
            return true;
        }

        return false;
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        passwords.remove(index);

        // TODO: Remove it from file
        saveFile(passwords);
    }

    public void updatePassword(Password password, int index) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        passwords.set(index, password);

        // TODO: Update the file with the new password information
        saveFile(passwords);
    }

    public void addPassword(Password password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        passwords.add(password);

        // TODO: Add the new password to the file
        saveFile(passwords);
    }

    // TODO: Tip: Break down each piece into individual methods, for example: generateSalt(), encryptPassword, generateKey(), saveFile, etc ...
    // TODO: Use these functions above, and it will make it easier! Once you know encryption, decryption, etc works, you just need to tie them in
    private static void generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);
        passwordFileSalt = saltString.getBytes();
    }

    private static String encryptPassword(String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte[] passwordBytes = password.getBytes();
        byte[] toEncrypt = new byte[passwordFileSalt.length+passwordBytes.length];
        
        for(int i = 0; i < passwordFileSalt.length; i++) {
            toEncrypt[i] = passwordFileSalt[i];
        }
        for(int i = 0; i < passwordBytes.length; i++) {
            toEncrypt[i + passwordFileSalt.length] = passwordBytes[i];
        }

        byte[] encryptedData = cipher.doFinal(toEncrypt);
        String messageString = new String(Base64.getEncoder().encode(encryptedData));
        return messageString;
    }

    private static String decryptPassword(String password) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(passwordFileKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] decodedData = Base64.getDecoder().decode(password);
        byte[] decryptedData = cipher.doFinal(decodedData);
        String messageString = new String(Arrays.copyOfRange(decryptedData, passwordFileSalt.length, decryptedData.length));

        return messageString;
    }

    private static void generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(passwordFilePassword.toCharArray(), passwordFileSalt, 600000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        passwordFileKey = privateKey.getEncoded();
    }

    private static void saveFile(List<Password> passwords) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
        StringBuffer buffer = new StringBuffer(new String(passwordFileSalt));
        buffer.append(separator);
        buffer.append(encryptPassword(verifyString));
        buffer.append('\n');

        for(int i = 0; i < passwords.size(); i++) {
            Password currentPassword = passwords.get(i);
            buffer.append(currentPassword.getLabel());
            buffer.append(separator);
            buffer.append(encryptPassword(currentPassword.getPassword()));
            if(i != passwords.size() - 1) {
                buffer.append('\n');
            }
        }

        FileWriter writer = new FileWriter(passwordFile);
        writer.write(buffer.toString());
        writer.close();
    }
}
