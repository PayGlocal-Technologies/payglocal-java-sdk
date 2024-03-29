package com.glocal;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JWS {

    private static final Logger logger = LogManager.getLogger(JWS.class.getName());

    private static final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.RS256;
    private static final String DIGEST_ALGORITHM = "SHA-256";
    private static final long TOKEN_EXPIRY_TIME_IN_MILLISECONDS = 300000L;

    // function to create JWS token
    // payload : JWE token
    // pvtKey : Private key of the merchant (Downloaded form gcc portal)
    // keyId : keyId of the Private Key
    // merchantId : merchant's merchantId (assigned by payglocal)
    public static String sign(String payload, PrivateKey pvtKey, String keyId, String merchantId) {
        if (pvtKey == null) {
            logger.error("PayGlocal RSA public key is null.");
            return null;
        }

        JWSSigner jwsSigner = new RSASSASigner(pvtKey);
        // Create JWE headers with some custom parameters
        // x-gl-merchantId -> merchantId
        // x-gl-enc -> is Payload encrypted (should be set as true)
        // issued-by -> merchantId
        // is-digested -> is payload digested (should be set as true)
        JWSHeader jwsHeader = new JWSHeader.Builder(JWS_ALGORITHM)
                .keyID(keyId)
                .customParam("x-gl-merchantId", merchantId)
                .customParam("x-gl-enc", "true")
                .customParam("issued-by", merchantId)
                .customParam("is-digested", "true")
                .build();

        JWSObject jwsObject = null;
        try {

            // Calculate the digest of the payload using SHA-256 algorithm
            MessageDigest messageDigestHelper = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] digestOfPayload = messageDigestHelper.digest(payload.getBytes());

            // Converted the digested payload to base64 encoder
            String base64EncodedDigestOfPayload = Base64.getEncoder().encodeToString(digestOfPayload);

            // Creating claimSet for JWS token
            // digest : digest of the payload
            // digestAlgorithm : SHA-256
            // iat : issued at time (it should be token creation time in epoch milliseconds)
            // exp -> expiry of the JWE token in long "300000L" (it is recommended to use 5 min as expiry )
            Map<String, Object> claimSetForJwsToken = new HashMap<>();
            claimSetForJwsToken.put("digest", base64EncodedDigestOfPayload);
            claimSetForJwsToken.put("digestAlgorithm", DIGEST_ALGORITHM);
            claimSetForJwsToken.put("iat", String.valueOf(Instant.now().toEpochMilli()));
            claimSetForJwsToken.put("exp", TOKEN_EXPIRY_TIME_IN_MILLISECONDS);

            logger.info("Created Auth token claim set");

            // Creating JWS token with JWS header and claimSet
            jwsObject = new JWSObject(jwsHeader, new Payload(claimSetForJwsToken));
            jwsObject.sign(jwsSigner);
            logger.info("Signed the Auth token.");
        } catch (NoSuchAlgorithmException | JOSEException e) {
            logger.error("Unable to create JWS token for request payload", e);
            return null;
        }
        return jwsObject.serialize();
    }

    // function to verify a JWS token using a public key
    // token : JWS token
    // publicKey : Public key of the PayGlocal (Downloaded form gcc portal)
    public boolean validate(String token, PublicKey publicKey) throws ParseException, JOSEException {
        if(token == null || token.isEmpty()){
            logger.error("JWS token is empty, cannot verify token");
            return false;
        }
        if(publicKey == null){
            logger.error("Public key is empty, cannot verify token");
            return false;
        }
        JWSObject jwsToken = JWSObject.parse(token);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        return jwsToken.verify(verifier);
    }

    // function to get the header section of a JWS token
    // token : JWS token
    public Map<String, Object> getHeader(String token) throws ParseException {
        if(token == null || token.isEmpty()){
            logger.error("JWS token is empty, cannot parse token");
            return null;
        }
        JWSObject jwsToken = JWSObject.parse(token);
        return jwsToken.getHeader().toJSONObject();
    }

    // function to get the claim set section of a JWS token
    // token : JWS token
    public Map<String, Object> getClaimSet(String token) throws ParseException {
        if(token == null || token.isEmpty()){
            logger.error("JWS token is empty, cannot parse token");
            return null;
        }
        JWSObject jwsToken = JWSObject.parse(token);
        return jwsToken.getPayload().toJSONObject();
    }
}
