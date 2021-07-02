package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class DomainInfoTest {

    private static DomainInfo before = new DomainInfo();
    private static SecurityDomainHost host = new SecurityDomainHost();

    @BeforeClass
    public static void setUpBefore() {
        before.setName("EXAMPLE");

        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        before.addHost("CA", host);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        DomainInfo afterJSON = JSONSerializer.fromJSON(json, DomainInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
