package com.example.fiaptechchallengelambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;

public class CpfAuthHandler implements RequestHandler<Map<String, Object>, Map<String, Object>> {

    private final CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
            .region(Region.of(System.getenv("AWS_REGION")))
            .credentialsProvider(DefaultCredentialsProvider.create())
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> input, Context context) {
        try {
            Map<String, Object> body = objectMapper.readValue((String) input.get("body"), Map.class);
            String cpf = (String) body.get("cpf");

            InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .clientId(System.getenv("CLIENT_ID"))
                    .authParameters(new HashMap<String, String>() {{
                        put("USERNAME", cpf);
                        put("PASSWORD", System.getenv("DEFAULT_PASS"));
                    }})
                    .build();

            InitiateAuthResponse response = cognitoClient.initiateAuth(authRequest);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("idToken", response.authenticationResult().idToken());
            responseBody.put("accessToken", response.authenticationResult().accessToken());
            responseBody.put("refreshToken", response.authenticationResult().refreshToken());

            return apiResponse(200, responseBody);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("message", "Erro ao autenticar");
            error.put("error", e.getMessage());
            return apiResponse(401, error);
        }
    }

    private Map<String, Object> apiResponse(int statusCode, Object body) {
        Map<String, Object> response = new HashMap<>();
        response.put("statusCode", statusCode);
        response.put("headers", Map.of("Content-Type", "application/json"));
        try {
            response.put("body", objectMapper.writeValueAsString(body));
        } catch (Exception e) {
            response.put("body", "{\"message\":\"Erro interno\"}");
        }
        return response;
    }
}