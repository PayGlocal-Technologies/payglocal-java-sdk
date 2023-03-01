package com.glocal;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PemFileReader {

    private static final Logger logger = LogManager.getLogger(PemFileReader.class.getName());

    private static final String PRIVATE_KEY_CERT_BEGINNING = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_CERT_ENDING = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_CERT_BEGINNING = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_CERT_ENDING = "-----END PUBLIC KEY-----";


    // function to read the PayGlocal public key file
    // fileName: path of the filename
    public static PublicKey getPublicKey(String fileName) {
        String keyAsBase64String = getBase64StringKeyFromPemFile(fileName);
        if (keyAsBase64String == null) {
            logger.error("Failed to extract PayGlocal RSA public key form PEM file");
            return null;
        }
        try {
            byte[] publicBytes = Base64.decodeBase64(keyAsBase64String);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            logger.info("Extracted PayGlocal RSA public key form PEM file.");
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Failed to extract PayGlocal RSA public key form PEM file", e);
            return null;
        }
    }

    // function to read the Private Key of the merchant
    // fileName: path of the filename
    public static PrivateKey getPrivateKey(String fileName) {
        String keyAsBase64String = getBase64StringKeyFromPemFile(fileName);
        if (keyAsBase64String == null) {
            logger.error("Failed to extract PayGlocal RSA private key form PEM file");
            return null;
        }
        try {
            byte[] pvtBytes = Base64.decodeBase64(keyAsBase64String);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pvtBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            logger.info("Extracted merchant RSA private key form PEM file.");
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Failed to extract merchant RSA private key form PEM file", e);
            return null;
        }
    }

    private static String getBase64StringKeyFromPemFile(String filename) {
        try {
            String base64EncodedKey = new String(Files.readAllBytes(Paths.get(filename)));
            base64EncodedKey = base64EncodedKey.replaceAll(PRIVATE_KEY_CERT_BEGINNING, "")
                    .replaceAll(PRIVATE_KEY_CERT_ENDING, "")
                    .replaceAll(PUBLIC_KEY_CERT_BEGINNING, "")
                    .replaceAll(PUBLIC_KEY_CERT_ENDING, "")
                    .replaceAll("\n", "")
                    .trim();
            return base64EncodedKey;
        } catch (Exception e) {
            logger.error(e.getLocalizedMessage());
            logger.error("Error while reading pem file", e);
            return null;
        }
    }
}
