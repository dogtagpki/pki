package com.netscape.certsrv.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class AuthorityDataTest {

    public static Logger logger = LoggerFactory.getLogger(AuthorityDataTest.class);

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
        logger.debug("JSON (before): " + json);

        AuthorityData afterJSON = JSONSerializer.fromJSON(json, AuthorityData.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
