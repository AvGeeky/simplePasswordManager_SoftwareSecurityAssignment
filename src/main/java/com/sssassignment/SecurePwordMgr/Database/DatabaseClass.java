package com.sssassignment.SecurePwordMgr.Database;

import com.sssassignment.SecurePwordMgr.HashingUtil.EncryptorDecryptor;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.IndexOptions;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import static com.mongodb.client.model.Filters.eq;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Repository
public class DatabaseClass {


    private String uri;
    private MongoClient mongoClient;
    private MongoDatabase database;
    private MongoCollection<Document> collection;
    private EncryptorDecryptor encryptorDecryptor;

    @Autowired
    public DatabaseClass( EncryptorDecryptor encryptorDecryptor) {
        try {
            uri = System.getenv("API_KEY");

            MongoClientSettings settings = MongoClientSettings.builder()
                    .applyConnectionString(new ConnectionString(uri))
                    .build();
            mongoClient = MongoClients.create(settings);

            database = mongoClient.getDatabase("Passwords");
            collection = database.getCollection("passwords");
        } catch (Exception e) {
            e.printStackTrace();
        }
       this.encryptorDecryptor = encryptorDecryptor;
    }





    public void insertPassword(String username, String hashedPassword) {
        Document passwordDoc = new Document("username", username)
                .append("hashed_password", hashedPassword);

        collection.insertOne(passwordDoc);

    }
    public Document getPasswordByUsername(String username) {
        Document query = new Document("username", username);
        return collection.find(query).first();
    }
    public  List<Map<String,String>> getAllPasswords() {
        List<Map<String,String>> passwords = new ArrayList<>();
        for (Document doc : collection.find()) {
            if (doc.containsKey("type") && "keys".equals(doc.getString("type"))) {
                continue;
            }
            HashMap<String,String> hm = new HashMap<>();
            hm.put("username", doc.getString("username"));
            hm.put("hashed_password", doc.getString("hashed_password"));
            passwords.add(hm);
        }
        return passwords;
    }

    public static String publicKeyToString(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
    public static String privateKeyToString(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public Map<String,Key> getOrGenerateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        Document keyDoc = collection.find(eq("type", "keys")).first();
        if (keyDoc != null) {

            String publicKeyStr = keyDoc.getString("pubkey");
            String privateKeyStr = keyDoc.getString("privkey");

            byte[] pubKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);

            X509EncodedKeySpec pubspec = new X509EncodedKeySpec(pubKeyBytes);
            PKCS8EncodedKeySpec prispec = new PKCS8EncodedKeySpec(privateKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey pubk =  keyFactory.generatePublic(pubspec);
            PrivateKey privk = keyFactory.generatePrivate(prispec);
            return Map.of("public", pubk, "private", privk);


        } else {
            KeyPair keys = encryptorDecryptor.generateKeyPair();

            String publicKeyStr = publicKeyToString(keys.getPublic());
            String privateKeyStr = privateKeyToString(keys.getPrivate());
            Document newKeyDoc = new Document("type", "keys")
                    .append("pubkey", publicKeyStr)
                    .append("privkey", privateKeyStr);

            collection.insertOne(newKeyDoc);
            return Map.of("public", keys.getPublic(), "private", keys.getPrivate());
        }
    }
//    public static void main(String[] args) {
//        DatabaseClass db = new DatabaseClass();
//        db.insertPassword("testuser", "hashedpassword123");
//        Document retrieved = db.getPasswordByUsername("testuser");
//        System.out.println("Retrieved password document: " + retrieved.toJson());
//        System.out.println("all retreived passwords: " + db.getAllPasswords());
//        for (Document doc : db.getAllPasswords()) {
//            System.out.println(doc.get("hashed_password"));
//        }
//    }
}
