package fr.gouv.dnum.proconnect.web.jwt;

public enum JwtAlgorithmEnum {

    RS256("RSA"), ES256("EC");

    private String algorithm;

    JwtAlgorithmEnum(String algo) {
        this.algorithm = algo;
    }

    public String getAlgorithm() {
        return algorithm;
    }

}
