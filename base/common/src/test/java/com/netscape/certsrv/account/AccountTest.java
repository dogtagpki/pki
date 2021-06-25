package com.netscape.certsrv.account;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AccountTest {

    private static Account before = new Account();

    @Before
    public void buildAccount() {
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
        System.out.println("XML (before): " + xml);

        Account afterXML = Account.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Account afterJSON = JSONSerializer.fromJSON(json, Account.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }
}
