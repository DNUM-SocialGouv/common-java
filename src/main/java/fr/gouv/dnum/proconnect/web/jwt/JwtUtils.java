package fr.gouv.dnum.proconnect.web.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import fr.gouv.dnum.proconnect.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public final class JwtUtils {

    private JwtUtils() {}

    static {
        // Ajouter Bouncy Castle comme fournisseur de sécurité
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Récupérer la clé publique à partir du JWKS (clé JSON Web Key Set) sans Jackson.
     */
    public static PublicKey getPublicKeyFromJwks(String kid, JwtAlgorithmEnum algorithm) throws Exception {
        String keyJson = getJSONKey(kid);

        // Récupérer les paramètres adaptés
        String keyType = extractJsonValue(keyJson, "kty");
        if ("RSA".equalsIgnoreCase(keyType) && algorithm == JwtAlgorithmEnum.RS256) {
            String n = extractJsonValue(keyJson, "n");
            String e = extractJsonValue(keyJson, "e");

            return buildRsaPublicKey(
                    Base64.getUrlDecoder().decode(n),
                    Base64.getUrlDecoder().decode(e)
            );
        } else if ("EC".equalsIgnoreCase(keyType) && algorithm == JwtAlgorithmEnum.ES256) {
            String crv = extractJsonValue(keyJson, "crv");
            String x = extractJsonValue(keyJson, "x");
            String y = extractJsonValue(keyJson, "y");

            return buildEcPublicKey(
                    crv,
                    Base64.getUrlDecoder().decode(x),
                    Base64.getUrlDecoder().decode(y)
            );
        }

        throw new IllegalArgumentException("Type de clé non supporté ou incompatibilité avec l'algorithme.");
    }

    private static String getJSONKey(String kid) throws IOException {
        URL url = URI.create(Constants.ProConnect.JWKS_ENDPOINT).toURL();

        try (java.io.InputStream is = url.openStream()) {
            String jwksJson = new String(is.readAllBytes());

            String keyJson = extractJsonForKey(jwksJson, kid);

            if (keyJson == null) {
                throw new IllegalArgumentException("Clé non trouvée pour kid : " + kid);
            }

            return keyJson;
        }
    }


    /**
     * Construire une clé publique RSA.
     */
    private static PublicKey buildRsaPublicKey(byte[] modulus, byte[] exponent) throws Exception {
        BigInteger modulusInt = new BigInteger(1, modulus);
        BigInteger exponentInt = new BigInteger(1, exponent);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulusInt, exponentInt);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * Construire une clé publique EC (courbe elliptique).
     */
    public static PublicKey buildEcPublicKey(String curveName, byte[] xBytes, byte[] yBytes) throws Exception {
        // Récupérer les spécifications de la courbe via Bouncy Castle
        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(curveName);
        if (bcSpec == null) {
            throw new IllegalArgumentException("Courbe non supportée : " + curveName);
        }

        // Convertir la courbe en spécification compatible avec Java
        ECParameterSpec ecSpec = new ECParameterSpec(
                new java.security.spec.EllipticCurve(
                        new java.security.spec.ECFieldFp(bcSpec.getCurve().getField().getCharacteristic()),
                        bcSpec.getCurve().getA().toBigInteger(),
                        bcSpec.getCurve().getB().toBigInteger()
                ),
                new ECPoint(
                        bcSpec.getG().getAffineXCoord().toBigInteger(),
                        bcSpec.getG().getAffineYCoord().toBigInteger()
                ),
                bcSpec.getN(),
                bcSpec.getH().intValue()
        );

        // Créer un point elliptique à partir des coordonnées X et Y
        ECPoint ecPoint = new ECPoint(
                new BigInteger(1, xBytes),
                new BigInteger(1, yBytes)
        );

        // Construire la spécification de la clé publique
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecSpec);

        // Générer la clé publique avec "KeyFactory"
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Valider et interpréter un JWT en fonction de l'algorithme.
     */
    public static Claims verifyJwt(String jwtToken, JwtAlgorithmEnum algorithm) throws Exception {
        String[] jwtParts = jwtToken.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(jwtParts[0]));
        ObjectMapper mapper = new ObjectMapper();
        String kid = mapper.readTree(headerJson).get("kid").asText();

        PublicKey publicKey = getPublicKeyFromJwks(kid, algorithm);

        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwtToken)
                .getPayload();
    }

    /**
     * Extraire la sous-structure JSON correspondant au kid.
     */
    private static String extractJsonForKey(String jwksJson, String kid) {
        int index = jwksJson.indexOf("\"kid\":\"" + kid + "\"");
        if (index == -1) {
            return null;
        }

        // Chercher la paire d'accolades correspondante
        int start = jwksJson.lastIndexOf("{", index);
        int end = jwksJson.indexOf("}", index) + 1;
        return jwksJson.substring(start, end);
    }

    /**
     * Extraire la valeur d'une clé dans une chaîne JSON très simple.
     */
    private static String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":\"";
        int index = json.indexOf(searchKey);
        if (index == -1) {
            return null;
        }

        int valueStart = index + searchKey.length();
        int valueEnd = json.indexOf("\"", valueStart);
        return json.substring(valueStart, valueEnd);
    }
}