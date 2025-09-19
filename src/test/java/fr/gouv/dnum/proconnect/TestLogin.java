package fr.gouv.dnum.proconnect;

import fr.gouv.dnum.proconnect.web.controller.ProConnectController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@TestMethodOrder(OrderAnnotation.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class TestLogin {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private HttpSession mockSession;

    private ProConnectController proConnectController;

    private static final String TEST_STATE = "init-123456689";
    private static final String TEST_CODE = "test_auth_code";
    private static final String TEST_ISS = Constants.ProConnect.ENVIRONMENT;
    private static final String TEST_ID_TOKEN = "test_id_token";
    private static final String TEST_EMAIL = "test@example.com";

    @BeforeEach
    void setUp() {
        // Utilisation du contrôleur réel sans injection de mocks problématiques
        proConnectController = new ProConnectController();
    }

    @Test
    @Order(1)
    void testGetProConnectLink_ShouldGenerateValidLink() {
        // Arrange
        when(mockRequest.getSession(true)).thenReturn(mockSession);

        // Act
        String result = proConnectController.getProConnectLink(mockRequest);

        System.out.println(result);

        // Assert
        assertNotNull(result, "L'URL générée ne doit pas être null");
        assertTrue(result.contains(Constants.ProConnect.AUTH_ENDPOINT),
                "L'URL doit contenir l'endpoint d'autorisation");
        assertTrue(result.contains("client_id=" + Constants.ProConnect.CLIENT_ID),
                "L'URL doit contenir le client_id");
        assertTrue(result.contains("response_type=code"),
                "L'URL doit contenir le type de réponse");
        assertTrue((result.contains("scope=openid%20profile%20email%20siret") || result.contains("scope=openid profile email siret")),
                "L'URL doit contenir les scopes");
        assertTrue((result.contains("redirect_uri=" + Constants.MyApplication.REDIRECT_URI.replace(":", "%3A").replace("/", "%2F"))) || result.contains("redirect_uri=" + Constants.MyApplication.REDIRECT_URI),
                "L'URL doit contenir l'URI de redirection encodée");

        // Vérifier que des valeurs sont stockées en session (appels réels)
        verify(mockSession, atLeastOnce()).setAttribute(eq("proConnectNonce"), any(Long.class));
        verify(mockSession, atLeastOnce()).setAttribute(eq("proConnectState"), any(String.class));
    }

    @Test
    @Order(2)
    void testGetProConnectToken_WithNoSession_ShouldReturnError() {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(null);

        // Act
        String result = proConnectController.getProConnectToken(mockRequest, TEST_CODE, TEST_STATE, TEST_ISS);

        // Assert
        assertEquals("Erreur", result, "Doit retourner 'Erreur' quand il n'y a pas de session");
    }

    @Test
    @Order(3)
    void testGetProConnectToken_WithInvalidState_ShouldReturnError() {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectState")).thenReturn("different_state");

        // Act
        String result = proConnectController.getProConnectToken(mockRequest, TEST_CODE, TEST_STATE, TEST_ISS);

        // Assert
        assertEquals("Erreur", result, "Doit retourner 'Erreur' quand le state est invalide");
    }

    @Test
    @Order(4)
    void testGetProConnectToken_WithMissingState_ShouldReturnError() {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectState")).thenReturn(null);

        // Act
        String result = proConnectController.getProConnectToken(mockRequest, TEST_CODE, TEST_STATE, TEST_ISS);

        // Assert
        assertEquals("Erreur", result, "Doit retourner 'Erreur' quand le state est manquant");
    }

    @Test
    @Order(5)
    void testGetProConnectToken_WithNetworkError_ShouldReturnError() {
        // Arrange - Setup session valide mais réseau inaccessible
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectState")).thenReturn(TEST_STATE);
        when(mockSession.getAttribute("proConnectNonce")).thenReturn(123456789L);

        // Act - L'appel HTTP échouera naturellement car l'endpoint n'est pas accessible
        String result = proConnectController.getProConnectToken(mockRequest, TEST_CODE, TEST_STATE, TEST_ISS);

        // Assert
        assertEquals("Erreur", result, "Doit retourner 'Erreur' en cas d'erreur réseau");
    }

    @Test
    @Order(6)
    void testDisconnect_WithValidSession_ShouldRedirect() throws IOException {
        // Arrange
        Long testNonce = 123456789L;
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectIdToken")).thenReturn(TEST_ID_TOKEN);
        when(mockSession.getAttribute("proConnectNonce")).thenReturn(testNonce);

        // Act
        proConnectController.disconnect(mockRequest, mockResponse);

        // Assert
        verify(mockResponse).sendRedirect(argThat(url ->
                url.contains(Constants.ProConnect.DISCONNECT_ENDPOINT) &&
                        url.contains("id_token_hint=" + TEST_ID_TOKEN) &&
                        url.contains("state=init-" + (testNonce - 100)) &&
                        url.contains("post_logout_redirect_uri")
        ));
    }

    @Test
    @Order(7)
    void testDisconnect_WithNoSession_ShouldNotRedirect() throws IOException {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(null);

        // Act
        proConnectController.disconnect(mockRequest, mockResponse);

        // Assert
        verify(mockResponse, never()).sendRedirect(anyString());
    }

    @Test
    @Order(8)
    void testDisconnect_WithPartialSessionData_ShouldStillRedirect() throws IOException {
        // Arrange - Seulement le nonce, pas d'id_token
        Long testNonce = 987654321L;
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectIdToken")).thenReturn(null);
        when(mockSession.getAttribute("proConnectNonce")).thenReturn(testNonce);

        // Act
        proConnectController.disconnect(mockRequest, mockResponse);

        // Assert
        verify(mockResponse).sendRedirect(argThat(url ->
                url.contains(Constants.ProConnect.DISCONNECT_ENDPOINT) &&
                        url.contains("state=init-" + (testNonce - 100)) &&
                        url.contains("post_logout_redirect_uri") &&
                        !url.contains("id_token_hint") // Pas d'id_token_hint si null
        ));
    }

    @Test
    @Order(9)
    void testLogout_WithValidSession_ShouldReturnUserInfo() {
        // Arrange
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("email", TEST_EMAIL);
        userInfo.put("given_name", "Jean");
        userInfo.put("family_name", "Dupont");
        userInfo.put("sub", "user123");

        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectUserInfo")).thenReturn(userInfo);
        when(mockSession.getId()).thenReturn("SESSION123");

        // Act
        String result = proConnectController.logout(mockRequest);

        // Assert
        assertNotNull(result, "Le résultat ne doit pas être null");
        assertTrue(result.contains("Déconnexion"), "Doit contenir le message de déconnexion");
        assertTrue(result.contains(TEST_EMAIL), "Doit contenir l'email de l'utilisateur");
        assertTrue(result.contains("Jean"), "Doit contenir le prénom");
        assertTrue(result.contains("Dupont"), "Doit contenir le nom de famille");
        assertTrue(result.contains("user123"), "Doit contenir le subject");

        verify(mockSession).invalidate();
    }

    @Test
    @Order(10)
    void testLogout_WithNoSession_ShouldReturnEmptyString() {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(null);

        // Act
        String result = proConnectController.logout(mockRequest);

        // Assert
        assertEquals("", result, "Doit retourner une chaîne vide quand il n'y a pas de session");
    }

    @Test
    @Order(11)
    void testLogout_WithSessionButNoUserInfo_ShouldReturnEmptyString() {
        // Arrange
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("proConnectUserInfo")).thenReturn(null);

        // Act
        String result = proConnectController.logout(mockRequest);

        // Assert
        assertEquals("", result, "Doit retourner une chaîne vide quand il n'y a pas d'infos utilisateur");
    }

    @Test
    @Order(12)
    void testGetProConnectLink_URLFormat_ShouldBeValid() {
        // Arrange
        when(mockRequest.getSession(true)).thenReturn(mockSession);

        // Act
        String result = proConnectController.getProConnectLink(mockRequest);

        // Assert
        // Vérification du format URL
        assertTrue(result.startsWith("https://"), "L'URL doit commencer par https://");
        assertTrue(result.contains("?"), "L'URL doit contenir des paramètres de requête");
        assertTrue(result.contains("&"), "L'URL doit contenir plusieurs paramètres");

        // Vérification des paramètres obligatoires
        String[] requiredParams = {
                "client_id=", "nonce=", "response_type=code",
                "scope=", "state=", "redirect_uri="
        };

        for (String param : requiredParams) {
            assertTrue(result.contains(param),
                    "L'URL doit contenir le paramètre: " + param);
        }
    }

    @Test
    @Order(13)
    void testConstants_ShouldHaveValidValues() {
        // Test des constantes pour s'assurer qu'elles sont bien définies
        assertNotNull(Constants.ProConnect.CLIENT_ID, "CLIENT_ID ne doit pas être null");
        assertNotNull(Constants.ProConnect.CLIENT_SECRET, "CLIENT_SECRET ne doit pas être null");
        assertNotNull(Constants.ProConnect.ENVIRONMENT, "ENVIRONMENT ne doit pas être null");

        assertTrue(Constants.ProConnect.ENVIRONMENT.startsWith("https://"),"ENVIRONMENT doit être une URL HTTPS");
        assertTrue(Constants.ProConnect.CLIENT_ID.length() > 10,"CLIENT_ID doit avoir une longueur suffisante");

        assertNotNull(Constants.MyApplication.REDIRECT_URI, "REDIRECT_URI ne doit pas être null");
        assertTrue(Constants.MyApplication.REDIRECT_URI.startsWith("http"),"REDIRECT_URI doit être une URL HTTP/HTTPS");
    }

}