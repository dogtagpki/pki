package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SystemCertDataTest {

    private static SystemCertData before = new SystemCertData();
    private static String[] dnsNames = {"lorem, ipsum"};

    @Before
    public void setUpBefore() {
        before.setCert("foo");
        before.setDNSNames(dnsNames);
        before.setKeyCurveName("bar");
        before.setKeySize("1024");
        before.setNickname("dolor");
        before.setProfile("sit");
        before.setRequest("amet");
        before.setSubjectDN("consectetur");
        before.setTag("adipiscing");
        before.setToken("elit");
        before.setType("sed");
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        SystemCertData afterXML = SystemCertData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SystemCertData afterJSON = SystemCertData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
