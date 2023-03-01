package com.glocal;

import com.nimbusds.jose.shaded.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args) {

        String payloadFileName = "/Users/mohit/Downloads/api-client/src/main/resources/requestpayload.json";
        String publicKeyFilePath = "//Users/mohit/Downloads/api-client/src/main/resources/keys/832ea6bb-5623-4dc3-96b1-c4be61e97324_payglocal_mid.pem";
        String publicKeyId = "832ea6bb-5623-4dc3-96b1-c4be61e97324";

        String privateKeyFilePath = "/Users/mohit/Downloads/api-client/src/main/resources/keys/a28b9bdc-2080-4141-9117-810a352d63d4_nihaluat12.pem";
        String privateKeyId = "a28b9bdc-2080-4141-9117-810a352d63d4";

        String merchantId = "nihaluat12";

        String statusPayload = "/gl/v1/payments/gl_523cef44-8e0d-4ad2-ab08-eb0f4c3ff72f/status";

        try {
            String jsonPayload = new String(Files.readAllBytes(Paths.get(payloadFileName)));
            JSONParser parser = new JSONParser(1);
            String payload = parser.parse(jsonPayload).toString();

            String jweToken = JWE.encrypt(payload, PemFileReader.getPublicKey(publicKeyFilePath), publicKeyId, merchantId);
            logger.info("Successfully create JWE token");
            logger.info("JWE token for transaction = {}", jweToken);

            String jwsToken = JWS.sign(jweToken, PemFileReader.getPrivateKey(privateKeyFilePath), privateKeyId, merchantId);
            logger.info("Successfully create JWS token");
            logger.info("JWS token for transaction = {}", jwsToken);

            // for status service payload = requestUri
            String jwsTokenStatus = JWS.sign(statusPayload, PemFileReader.getPrivateKey(privateKeyFilePath), privateKeyId, merchantId);
            logger.info("JWS token for Status call = {}", jwsTokenStatus);
        }catch (Exception e){
            logger.error("Error wile creating jwe/jws token", e);
        }

    }
}
