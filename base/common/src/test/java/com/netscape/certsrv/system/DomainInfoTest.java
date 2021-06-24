package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class DomainInfoTest {

    private static DomainInfo before = new DomainInfo();
    private static DomainInfo info = new DomainInfo();
    private static SecurityDomainHost host = new SecurityDomainHost();

    @BeforeClass
    public static void setUpBefore() {
        info.setName("EXAMPLE");

        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        info.addHost("CA", host);
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        DomainInfo afterXML = DomainInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        DomainInfo afterJSON = DomainInfo.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
