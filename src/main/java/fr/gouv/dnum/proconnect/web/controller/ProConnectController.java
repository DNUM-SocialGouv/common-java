package fr.gouv.dnum.proconnect.web.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.gouv.dnum.proconnect.web.jwt.JwtAlgorithmEnum;
import fr.gouv.dnum.proconnect.web.jwt.JwtUtils;
import fr.gouv.dnum.proconnect.web.response.BodyResponse;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import fr.gouv.dnum.proconnect.Constants;

import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.util.*;

@Slf4j
@RestController
public class ProConnectController {

    private static final String SESSION_NONCE = "proConnectNonce";
    private static final String SESSION_STATE = "proConnectState";
    private static final String SESSION_ACCESS_TOKEN = "proConnectAccessToken";
    private static final String SESSION_ID_TOKEN = "proConnectIdToken";
    private static final String SESSION_USER_INFO = "proConnectUserInfo";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    private String getLink(HttpServletRequest request) {
        long nonce = secureRandom.nextLong();
        if (nonce < 0) {
            nonce = Math.abs(nonce);
        }
        String state = "init-" + (nonce - 100);

        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_NONCE, nonce);
        session.setAttribute(SESSION_STATE, state);

        // Construction sûre de l'URL avec encodage correct
        String url = org.springframework.web.util.UriComponentsBuilder
                .fromHttpUrl(Constants.ProConnect.AUTH_ENDPOINT)
                .queryParam("client_id", Constants.ProConnect.CLIENT_ID)
                .queryParam("nonce", String.valueOf(nonce))
                .queryParam("response_type", "code")
                .queryParam("scope", "openid profile email siret")
                .queryParam("state", state)
                .queryParam("redirect_uri", Constants.MyApplication.REDIRECT_URI)
                .build(false) // ne pas ré-encoder
                .toUriString();

        return url;
    }

    @Operation(
            summary = "Permets de générer une URL pour le bouton \"Se connecter avec ProConnect\"",
            description = "Retourne une URL de connexion ProConnect avec les paramètres nécessaires",
            tags = {"Point d'entrée"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "URL de connexion ProConnect générée avec succès",
                    content = @Content(
                            mediaType = "text/plain",
                            schema = @Schema(type = "string",
                                    example = "https://fca.integ01.dev-agentconnect.fr/api/v2/authorize?client_id=xxx&nonce=123&response_type=code&scope=openid profile email&state=init-123&redirect_uri=http://localhost:8081/api/proconnect/valid_code")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Error.class)
                    )
            )
    })
    @GetMapping("/proconnect/link")
    public String getProConnectLink(HttpServletRequest request) {
        return getLink(request);
    }

    @Hidden
    @Operation(
            summary = "Validation du code d'autorisation ProConnect",
            description = "Endpoint appelé par ProConnect après l'authentification réussie. " +
                    "Valide le code d'autorisation, récupère les tokens et les informations utilisateur"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Connexion réussie",
                    content = @Content(
                            mediaType = "text/plain",
                            schema = @Schema(type = "string", example = "[Connecté : user@example.com]")
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Paramètres invalides",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Error.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content(
                            mediaType = "text/plain",
                            schema = @Schema(type = "string", example = "Erreur")
                    )
            )
    })
    @GetMapping("/proconnect/valid_code")
    public String getProConnectToken(HttpServletRequest request,
                                   @RequestParam("code") String code,
                                   @RequestParam("state") String state,
                                   @RequestParam("iss") String iss) {

        String email = null;

        JwtAlgorithmEnum jwtAlgorithmEnum = JwtAlgorithmEnum.ES256;

        log.info("code : " + code);
        log.info("state : " + state);
        log.info("iss : " + iss);

        HttpSession session = request.getSession(false);
        if (session == null) {
            log.warn("Session introuvable lors du callback ProConnect");
            return "Erreur";
        }

        String expectedState = (String) session.getAttribute(SESSION_STATE);
        if (expectedState == null || !expectedState.equals(state)) {
            log.warn("State invalide. Attendu={}, Reçu={}", expectedState, state);
            return "Erreur";
        }

        // possible de valider l'iss ici si il y a besoin

        // Préparer les paramètres en tant que paires clé=valeur encodées
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("grant_type", "authorization_code");
        form.add("client_id", Constants.ProConnect.CLIENT_ID);
        form.add("client_secret", Constants.ProConnect.CLIENT_SECRET);
        form.add("redirect_uri", Constants.MyApplication.REDIRECT_URI);

        // Créer une instance de RestTemplate
        RestTemplate restTemplate = new RestTemplate();

        // Configuration des headers (exemple : JSON)
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Créer un HttpEntity qui contient le body et les headers
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(form, headers);

        // Effectuer la requête POST
        try {
            ResponseEntity<String> tokenResponse = restTemplate.postForEntity(Constants.ProConnect.TOKEN_ENDPOINT, requestEntity, String.class);

            // Afficher la réponse (ou la traiter selon vos besoins)
            log.info("Réponse : " + tokenResponse.getBody());

            String responseBody = tokenResponse.getBody();

            JsonNode jsonObject = objectMapper.readTree(responseBody); // Parse JSON en un arbre JsonNode

            // Convertir les données JSON en objet BodyResponse
            BodyResponse bodyResponse = new BodyResponse();
            bodyResponse.setAccessToken(jsonObject.get("access_token").asText());
            bodyResponse.setIdToken(jsonObject.get("id_token").asText());
            bodyResponse.setRefreshToken(jsonObject.get("refresh_token").asText());
            bodyResponse.setTokenType(jsonObject.get("token_type").asText());
            bodyResponse.setExpiresIn(jsonObject.get("expires_in").asLong());

            // Afficher les informations
            log.info("Access Token : " + bodyResponse.getAccessToken());
            log.info("Refresh Token : " + bodyResponse.getRefreshToken());
            log.info("Token Type : " + bodyResponse.getTokenType());
            log.info("Expires In : " + bodyResponse.getExpiresIn());
            log.info("ID Token : " + bodyResponse.getIdToken());

            // Décoder le JWT et le lire
            Claims claims = JwtUtils.verifyJwt(bodyResponse.getIdToken(), jwtAlgorithmEnum);


            String issuer = claims.getIssuer();
            LinkedHashSet<String> aud = claims.get("aud", LinkedHashSet.class);
            String nonce = claims.get("nonce", String.class);
            Date exp = claims.getExpiration();

            if (!issuer.startsWith(Constants.ProConnect.ENVIRONMENT))
                throw new SecurityException("bad iss");

            if (!aud.contains(Constants.ProConnect.CLIENT_ID))
                throw new SecurityException("bad aud");

            if (exp == null || exp.before(new Date(System.currentTimeMillis() - 120000)))
                throw new SecurityException("expired");

            System.out.println("nonce = " + nonce);
            System.out.println("session nonce = " + session.getAttribute(SESSION_NONCE));

            if (!Objects.equals(nonce, session.getAttribute(SESSION_NONCE).toString()))
                throw new SecurityException("bad nonce");
            /*
            if (!expectedIssuer.equals(issuer)) throw new SecurityException("bad iss");
            if (aud == null || !aud.contains(expectedClientId)) throw new SecurityException("bad aud");
            if (exp == null || exp.before(new Date(System.currentTimeMillis() - 120_000))) throw new SecurityException("expired");
            if (!Objects.equals(nonce, sessionNonce)) throw new SecurityException("bad nonce");
            */

            // Afficher les informations pour valider le résultat
            log.info("JWT vérifié avec succès !");
            log.info("Subject : " + claims.getSubject());
            log.info("Expiration : " + claims.getExpiration());

            log.info("Access token : " + bodyResponse.getAccessToken());

            Map<String, Object> userInfo = getUserInfo(bodyResponse.getAccessToken(), jwtAlgorithmEnum);
            for (Map.Entry<String, Object> entry : userInfo.entrySet()) {
                log.info(entry.getKey() + " => " + entry.getValue());
                if (entry.getKey().equals("email")) {
                    email = entry.getValue().toString();
                }
            }

            session.setAttribute(SESSION_ACCESS_TOKEN, bodyResponse.getAccessToken());
            session.setAttribute(SESSION_ID_TOKEN, bodyResponse.getIdToken());
            session.setAttribute(SESSION_USER_INFO, userInfo);

            return "[Connecté : " + email+"]";

        } catch (Exception e) {
            // Gestion des erreurs
            log.error(e.getMessage(), e);
        }

        return "Erreur";
    }

    private Map<String, Object> getUserInfo(String accessToken, JwtAlgorithmEnum jwtAlgorithmEnum) throws Exception {

        log.info("Get User Info :: accessToken : " + accessToken);

        // Préparer l'en-tête Authorization avec le token d'accès
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        // Construire la requête
        RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, new URI(Constants.ProConnect.USERINFO_ENDPOINT));

        // Appeler le endpoint "/userinfo" via RestTemplate
        RestTemplate restTemplate = new RestTemplate();

        ResponseEntity<String> resp = restTemplate.exchange(request.getUrl(), HttpMethod.GET, request, String.class);

        Claims claims_ = JwtUtils.verifyJwt(resp.getBody(), jwtAlgorithmEnum);

        Map<String, Object> userInfo = new HashMap<>();
        claims_.forEach((k, v) -> {
            log.info(k + " : " + v);
            userInfo.put(k, v);
        });
        return userInfo;
    }

    @Operation(
            summary = "Déconnexion de ProConnect",
            description = "Déconnecte l'utilisateur de ProConnect en le redirigeant vers l'endpoint de déconnexion avec les paramètres nécessaires",
            tags = {"Déconnexion"}
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "302",
                    description = "Redirection vers la page de déconnexion ProConnect",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Erreur interne du serveur",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Error.class)
                    )
            )
    })
    @GetMapping("/proconnect/disconnect")
    public void disconnect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            log.info("Logout Session ID : " + session.getId());
            String idToken = (String) session.getAttribute(SESSION_ID_TOKEN);
            Long nonce = (Long) session.getAttribute(SESSION_NONCE);

            org.springframework.web.util.UriComponentsBuilder b = org.springframework.web.util.UriComponentsBuilder
                    .fromHttpUrl(Constants.ProConnect.DISCONNECT_ENDPOINT);

            if (idToken != null) {
                b.queryParam("id_token_hint", idToken);
            }
            if (nonce != null) {
                b.queryParam("state", "init-" + (nonce - 100));
            }
            b.queryParam("post_logout_redirect_uri", Constants.MyApplication.POST_INTERNAL_LOGOUT_REDIRECT_URI);

            String url = b.build(true).toUriString();
            response.sendRedirect(url);

        } else {
            log.info("No session found");
        }
    }

    @Hidden
    @GetMapping("/proconnect/logout")
    public String logout(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        // Récupère la session si existante
        HttpSession session = request.getSession(false);
        if (session!=null && session.getAttribute(SESSION_USER_INFO)!=null) {
            // Récupère les infos user gardées en session
            Map<String, Object> userInfo = (Map<String, Object>) session.getAttribute(SESSION_USER_INFO);
            log.info("Internal logout Session ID : " + session.getId());
            // Invalidation de la session
            session.invalidate();
            // Construction de la réponse String
            sb.append("Déconnexion<br/><br/>");
            userInfo.forEach((k, v) -> {
                sb.append(k).append(" : ").append(v).append("<br/>");
            });
        }
        return sb.toString();
    }
}
