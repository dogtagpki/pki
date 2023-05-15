package com.netscape.certsrv.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AuthorityDataTest {

    private static AuthorityData before = new AuthorityData();

    @BeforeAll
    public static void setUpBefore() {
        before.setDescription("Test AuthorityData");
        before.setDn("dn");
        before.setEnabled(true);
        before.setId("testuser");
        before.setIsHostAuthority(true);
        before.setIssuerDN("issuerDN");
        before.setParentID("parentID");
        before.setReady(false);
        before.setSerial(BigInteger.valueOf(1));
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AuthorityData afterJSON = JSONSerializer.fromJSON(json, AuthorityData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
