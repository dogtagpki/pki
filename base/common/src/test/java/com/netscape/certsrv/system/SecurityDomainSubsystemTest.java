package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SecurityDomainSubsystemTest {

    private static SecurityDomainSubsystem before = new SecurityDomainSubsystem();
    private static SecurityDomainHost host = new SecurityDomainHost();

    @Before
    public void setUpBefore() {
        before.setName("CA");

        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        before.addHost(host);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        SecurityDomainSubsystem afterXML = SecurityDomainSubsystem.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SecurityDomainSubsystem afterJSON = SecurityDomainSubsystem.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
