package com.glocal;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JWE {

    private static final Logger logger = LogManager.getLogger(JWE.class.getName());

    private static final JWEAlgorithm JWE_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    private static final EncryptionMethod JWE_ENCRYPTION_METHOD = EncryptionMethod.A128CBC_HS256;
    private static final long TOKEN_EXPIRY_TIME_IN_MILLISECONDS = 300000L;

    // function to create JWE token
    // payload : non-encrypted payload (json stringified)
    // pubKey : Public key of the PayGlocal (Downloaded form gcc portal)
    // keyId : keyId of the Public Key
    // merchantId : merchant's merchantId (assigned by payglocal)
    public static String encrypt(String payload, PublicKey pubKey, String keyId, String merchantId) {
        if (pubKey == null) {
            logger.error("PayGlocal RSA public key is null.");
            return null;
        }
        // Create JWE headers with some custom parameters
        // iat -> issued at time (it should be token creation time in epoch milliseconds)
        // exp -> expiry of the JWE token in long "300000L" (it is recommended to use 5 min as expiry )
        // issued-by -> merchantId
        RSAPublicKey rsaPublicKey = (RSAPublicKey) pubKey;
        JWEHeader jweHeader = new JWEHeader.Builder(JWE_ALGORITHM, JWE_ENCRYPTION_METHOD)
                .keyID(keyId)
                .customParam("iat", String.valueOf(Instant.now().toEpochMilli()))
                .customParam("exp", TOKEN_EXPIRY_TIME_IN_MILLISECONDS)
                .customParam("issued-by", merchantId)
                .build();
        logger.info("Created JWE token header");

        // Note: here the payload is non-encrypted, and it should be "stringify" json payload
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(payload));
        KeyGenerator keyGenerator;
        try {
            // generate the jwe token using "RSA_OAEP_256" algorithm (mentioned in JWE header)
            // and the encryption method is "A128CBC_HS256" (for encryption of payload)
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(JWE_ENCRYPTION_METHOD.cekBitLength());
            SecretKey contentEncryptionKey = keyGenerator.generateKey();
            jweObject.encrypt(new RSAEncrypter(rsaPublicKey, contentEncryptionKey));
            logger.info("Created JWE token for encrypting request payload.");
        } catch (NoSuchAlgorithmException | JOSEException e) {
            logger.error("Unable to create JWE token for request payload encryption", e);
            return null;
        }
        return jweObject.serialize();
    }
}
