package com.netscape.ca;

import java.io.ByteArrayOutputStream;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CTParser {


    public static String composeRequest(String base64Cert) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        try {
            JsonFactory jsonFactory = new JsonFactory();
            JsonGenerator jsonGenerator = jsonFactory.createGenerator(outputStream);

            jsonGenerator.writeStartObject();

            jsonGenerator.writeStringField("chain", base64Cert);

            jsonGenerator.writeEndObject();
            jsonGenerator.close();

            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return outputStream.toString();
    }

    public static void main(String args[]) {
        // Composing Request - To JSON
        String toJson = composeRequest("MIID9zCCAl+gAwIBAgIBBjANBgkqhkiG9w0BAQsFADA4M"
                + "RYwFAYDVQQKDA1GRURPUkEuT0ZGSUNFMR4wHAYDVQQDDBVDZXJ0aWZpY2F0ZSBBdXRob"
                + "3JpdHkwHhcNMTkxMjA5MTQ0MjI5WhcNMjExMTI4MTQ0MjI5WjAvMRYwFAYDVQQKDA1GRU"
                + "RPUkEuT0ZGSUNFMRUwEwYDVQQDDAxpcGEtY2EtYWdlbnQwggEiMA0GCSqGSIb3DQEBAQU"
                + "AA4IBDwAwggEKAoIBAQC4q4I+U33yOjekEJvr/Kqj48LYRUvLbnvTWEc1rIL9xG70vPd+"
                + "xAnwTjWyTeMX0fjLkZOtxxiEWxdLGOPneAMggoB/7PC6ERGkXR0riLxx43XzCwNF0AlYTu"
                + "mx+WW8zEKaNyTkfysvyW75s4AsGXcQV7x+R29iZsig9g5JJLc4TorON2/ahbRyNz68w2D"
                + "VBHAlPv06CcTiUpi3Ozvxlc0+bQjD5c2+1pbgK6KeA1MTMjB7vgbLgKp4qZycYHwNBbHJ"
                + "GSvrguWezpt9db1zvxasnSJ0XpShg0pKoRNRcXoddGUrJe482z1F2iWt9+LQsorvEjozx"
                + "3ssHzQUgmKG4pJjAgMBAAGjgZQwgZEwHwYDVR0jBBgwFoAUQFyGZItysxJGUvFF1lqfym"
                + "84tRswPwYIKwYBBQUHAQEEMzAxMC8GCCsGAQUFBzABhiNodHRwOi8vaXBhLWNhLmZlZG9y"
                + "YS5vZmZpY2UvY2Evb2NzcDAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAw"
                + "IGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4IBgQBgNSNJM6xSWxIps2sY00eYLpTWcXQb"
                + "Lhbni7zqCUrHv1cXKcIxsMHCXuj8Ly6Uzwn61LBKRBR98Egj/Vx+ERqjFOFoXj6/KeWi/i"
                + "KQ1iw6Tm9npX+yvEzBBIzvOXEeKH19LiTxW08kY3JIv7+i/AOWRC6WzdkpukgjUlwK2yiE"
                + "Vt+k8SigrHEkSag5M1U1AiEzaZn5aSOiTKimZRoxF51EoqWsdZV7QmSQlmNgOPaoL+W5k9"
                + "+IG4HJuUcLRLgYRyeewN59Rh/s9Ok+P33Q3ywWIYIENwq+/7rj/phJFxkBD4RrcqJw0QoX"
                + "w4B+jcK0uIVD9Jpvfi3yAmmKmJ5shl0rksyUzEfdWaTnTJy1LES90eGuiL4qUY3vplzkE"
                + "/Sb+m0KxJaHF9sVLPHrt83bzvrKueyojrB9es9Lnq1b5ui0kuUlgwnbyLcmWCEyKrMOH89"
                + "Mqg943FBUfdEmkHhuufNgrNVzimZXKBxHgWheZ3Us7jzkcm1BEUb1j69KoEGxsoM=");

        System.out.println("==== Example Request ====");
        System.out.println(toJson);

        // Parsing Response - Parsing JSON

        String exampleJSON = "{\"sct_version\":0,\"id\":\"sMyD5aX5fWuvfAnMKEkEhyrH6IsTLGNQt8b9JuFsbHc=\",\"timestamp\":1559693600150,\"extensions\":\"\",\"signature\":\"BAMASDBGAiEAjTzhTmOKcs2ZKF/P7HUAGl9YYtqZZvtDwZFWbI4/1swCIQDC9pbgYY7dYbsmiP0xFjq/lVZo34AqXGwQibChGoxulA==\"}";

        ObjectMapper mapper = new ObjectMapper();
        CTResponse response;
        try {
            response = mapper.readValue(exampleJSON, CTResponse.class);
            System.out.println("===== Example Response ===== \n" + response);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

class CTResponse {

    private int sct_version;
    private String id;
    private long timestamp;
    private String extensions;
    private String signature;

    public CTResponse() {}

    public int getSct_version() {
        return sct_version;
    }

    public void setSct_version(int sct_version) {
        this.sct_version = sct_version;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getExtensions() {
        return extensions;
    }

    public void setExtensions(String extensions) {
        this.extensions = extensions;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String toString() {
        return "CTResponse [ \nsct_version: " + sct_version + ", \nid: " + id + ", \ntimestamp" + timestamp
                + ", \nextensions: " + extensions + ", \nsignature: " + signature + " \n]";
    }

}
