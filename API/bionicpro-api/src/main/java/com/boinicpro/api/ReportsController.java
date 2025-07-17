package com.boinicpro.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.TokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.SystemPropertiesJsonParserFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class ReportsController {

    @RequestMapping("/reports")
    public ResponseEntity<String> reports(@RequestHeader("Authorization") String authorizationHeader) throws IOException {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Authorization header missing or invalid.");
        }

        String token = authorizationHeader.substring("Bearer ".length());

        // Это работает на localhost и будет работать на ендпоинтах,
        // но не работает в docker, т.к. issuer http://localhost:8080 и http://keycloak:8080 разные
//        TokenIntrospectionResponse response = createClient().protection().introspectRequestingPartyToken(token);
//        if (response.getActive() == null || !response.getActive()) {
//            return ResponseEntity.status(401).body("Token verification failed");
//        }

        AccessToken accessToken;
        try {
            accessToken = TokenVerifier.create(token, AccessToken.class).getToken();
        } catch (VerificationException e) {
            return ResponseEntity.status(401).body("Token parse failed");
        }

        if (accessToken.getRealmAccess() == null || accessToken.getRealmAccess().getRoles() == null || accessToken.getRealmAccess().getRoles().isEmpty()) {
            return ResponseEntity.status(401).body("Denied access token");
        }

        if (!accessToken.getRealmAccess().getRoles().contains("prothetic_user")) {
            return ResponseEntity.status(401).body("Denied access token");
        }

        return ResponseEntity.ok("Report successfully generated!");
    }

    private AuthzClient createClient() throws IOException {
        InputStream configStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("keycloak.json");
        ObjectMapper mapper = new ObjectMapper(new SystemPropertiesJsonParserFactory());
        Configuration configuration = mapper.readValue(configStream, Configuration.class);
        String keycloakUrl = System.getenv("KEYCLOAK_URL");
        // String keycloakUrl = "http://localhost:8080";
        System.out.println("Keycloak URL: " + keycloakUrl);
        configuration.setAuthServerUrl(keycloakUrl);
        return AuthzClient.create(configuration);
    }
}