package com.netscape.certsrv.account;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class AccountTest {

    public static Logger logger = LoggerFactory.getLogger(AccountTest.class);

    private static Account before = new Account();

    @BeforeAll
    public static void buildAccount() {
        // Arrange
        before.setID("testuser");
        before.setFullName("Test User");
        before.setEmail("testuser@example.com");
        before.setRoles(Arrays.asList("admin", "agent"));
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        logger.debug("XML (before): " + xml);

        Account afterXML = Account.fromXML(xml);
        logger.debug("XML (after): " + afterXML.toXML());

        // Assert
        assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        Account afterJSON = JSONSerializer.fromJSON(json, Account.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }
}
