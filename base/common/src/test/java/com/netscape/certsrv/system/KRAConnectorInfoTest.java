package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class KRAConnectorInfoTest {

    private static KRAConnectorInfo before = new KRAConnectorInfo();

    @BeforeAll
    public static void setUpBefore() {
        before.setEnable("true");
        before.setHost("host1.example.com");
        before.setLocal("false");
        before.setPort("8443");
        before.setTimeout("30");
        before.setUri("");
        before.setTransportCertNickname("KRA Transport Certificate");
        before.setTransportCert(
            "MIIDnDCCAoSgAwIBAgIBDzANBgkqhkiG9w0BAQsFADBGMSMwIQYDVQQKExpyZWRo" +
            "YXQuY29tIFNlY3VyaXR5IERvbWFpbjEfMB0GA1UEAxMWQ0EgU2lnbmluZyBDZXJ0" +
            "aWZpY2F0ZTAeFw0xMzAxMDkyMTE5MDBaFw0xNDEyMzAyMTE5MDBaMEkxIzAhBgNV" +
            "BAoTGnJlZGhhdC5jb20gU2VjdXJpdHkgRG9tYWluMSIwIAYDVQQDExlEUk0gVHJh" +
            "bnNwb3J0IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC" +
            "AQEAqayxDggWH9Cld0O/j+HDfv7cLQexYiaDq/sEcFPYkREGisaxZggiovqLfMkz" +
            "rSjutVtHuIEb3pU9frHYUjskbzdMbeU3nqDnA/ZPUw+YJe/6l19AbieADVB/L+6p" +
            "TkNMwS/xsQIRnalYW9R4rebw3WiwQFxVHIorGL9qxUS5d12uguJokH/CbIML9Pek" +
            "NgAZRGx87J4UkqTe5FImuEX8EwVWoW8Huc8QDthk1w5osz3jOTefwrJBEiI54d9F" +
            "hl4O8ckXfecCAPYfn0Mi54I1VAbSRZEiq6GJ/xrN1IwLkaG7EmXtLU2IkaMz62MJ" +
            "UmgBrlrtRj1eyAXLGwS4Fh4NVwIDAQABo4GRMIGOMB8GA1UdIwQYMBaAFMjscbmB" +
            "k0Gz2wVxGWkn9bjSA88wMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0" +
            "cDovL2FsZWUtd29ya3BjLnJlZGhhdC5jb206ODI4MC9jYS9vY3NwMA4GA1UdDwEB" +
            "/wQEAwIE8DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEA" +
            "gCCPZ5+pkxZDgKJpisJ8/5TfKtN/q5pO8CNKIM9Cz78ucGEaR2lzJVH5EOdO2ZM6" +
            "y+5AhK2hcKifNI3DPAfYdYsSVBR6Mrij4/aAMZlqtKjlNs/LJ2TdKGRxxYsEAQL+" +
            "OToCfXijDh0kzQ9oSII+9fBCWljkq/K89bSGcwR/y1v+ll+z9Wci+QAFKUzmqZyL" +
            "eEbOOmYhgvVSnYV1XdB6lbWQOOdpytvECl1UaQUSsDfJkk8mH1Fkl0dnrChh7mXM" +
            "2ZBYwBsI2DhAyWBKQgQfgxQwxmobbg6BVnn9/CW7gJ0Gwb+VJEvRtaBOnjliP74/" +
            "Jb+fenCZE47zRNCDubBe+Q==");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KRAConnectorInfo afterJSON = JSONSerializer.fromJSON(json, KRAConnectorInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
