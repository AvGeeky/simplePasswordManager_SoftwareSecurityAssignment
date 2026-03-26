package com.sssassignment.SecurePwordMgr.Controller;

import com.sssassignment.SecurePwordMgr.Database.DatabaseClass;
import com.sssassignment.SecurePwordMgr.HashingUtil.EncryptorDecryptor;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@RestController
public class ServiceController {
    DatabaseClass database;
    EncryptorDecryptor rsa;
    PublicKey publicKey;
    PrivateKey privateKey;



    @Autowired
    public ServiceController(DatabaseClass database, EncryptorDecryptor rsa){
        this.database = database;
        this.rsa = rsa;
    }
    @PostConstruct
    public void loadKeys() {
        try {
            Map<String, Key> keys = database.getOrGenerateKey();
            publicKey = (PublicKey) keys.get("public");
            privateKey = (PrivateKey) keys.get("private");
        }
        catch (Exception e) {
                throw new RuntimeException("Failed to load keys", e);
        }

    }



    @PostMapping("/addPassword")
    public ResponseEntity<Map<String,Object>> addPassword(@RequestBody Map<String,Object> data) {
        Map<String,Object> response = new java.util.HashMap<>();
        try {
            String username = (String) data.get("username");
            String password = (String) data.get("password");
            String encryptedPassword = rsa.encrypt(password, publicKey);
            database.insertPassword(username, encryptedPassword);
            response.put("status", "success");
            response.put("message", "Password added successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("status", "error", "message", "Failed to add password"));
        }

    }
    @GetMapping("/getAllPasswords")
    public ResponseEntity<Map<String,Object>> getAllPasswords() {
        Map<String,Object> response = new java.util.HashMap<>();
        try {
            List<Map<String,String>> passwords = database.getAllPasswords();
            List<Map<String,String>> decryptedPasswords = new ArrayList<>();
            for (Map<String,String> entry : passwords) {
                String decryptedPassword = rsa.decrypt(entry.get("hashed_password"), privateKey);
                Map<String,String> decryptedEntry = new java.util.HashMap<>();
                decryptedEntry.put("username", entry.get("username"));
                decryptedEntry.put("password", decryptedPassword);
                decryptedPasswords.add(decryptedEntry);
            }
            response.put("status", "success");
            response.put("hashedPasswords", passwords);
            response.put("decryptedPasswords", decryptedPasswords);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("status", "error", "message", "Failed to retrieve passwords"));
        }
    }



}
