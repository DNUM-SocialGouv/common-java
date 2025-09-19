package fr.gouv.dnum.proconnect;

public class Constants {

    // côté ProConnect
    public static final class ProConnect {

        private static final String ENVIRONMENT_INTERNET_INTEGRATION = "fca.integ01.dev-agentconnect.fr";
        private static final String ENVIRONMENT_INTERNET_PRODUCTION = "auth.agentconnect.gouv.fr";
        private static final String ENVIRONMENT_RIE_INTEGRATION = "fca.integ02.agentconnect.rie.gouv.fr";
        private static final String ENVIRONMENT_RIE_PRODUCTION = "auth.agentconnect.rie.gouv.fr";

        public static final String ENVIRONMENT = "https://" + ENVIRONMENT_INTERNET_INTEGRATION;

        public static final String USERINFO_ENDPOINT = ENVIRONMENT + "/api/v2/userinfo";

        public static final String AUTH_ENDPOINT = ENVIRONMENT + "/api/v2/authorize";
        public static final String TOKEN_ENDPOINT = ENVIRONMENT + "/api/v2/token";
        public static final String DISCONNECT_ENDPOINT = ENVIRONMENT + "/api/v2/session/end";
        public static final String JWKS_ENDPOINT = ENVIRONMENT + "/api/v2/jwks";

        public static final String CLIENT_ID = "to define";
        public static final String CLIENT_SECRET = "to define";

    }

    // côté Application DNUM
    public static final class MyApplication {
        // doivent correspondre à ce qui a été configuré dans le BO ProConnect
        public static final String REDIRECT_URI = "http://localhost:8080/proconnect/valid_code";
        public static final String POST_INTERNAL_LOGOUT_REDIRECT_URI = "http://localhost:8080/proconnect/logout";
    }

}
