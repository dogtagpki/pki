package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class SecurityDomainHostTest {

    private static SecurityDomainHost before = new SecurityDomainHost();

    @Before
    public void setUpBefore() {
        before.setId("CA localhost 8443");
        before.setHostname("localhost");
        before.setPort("8080");
        before.setSecurePort("8443");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        SecurityDomainHost afterXML = SecurityDomainHost.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SecurityDomainHost afterJSON = JSONSerializer.fromJSON(json, SecurityDomainHost.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
