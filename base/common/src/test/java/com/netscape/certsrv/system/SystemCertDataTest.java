package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

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
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        SystemCertData afterJSON = JSONSerializer.fromJSON(json, SystemCertData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
