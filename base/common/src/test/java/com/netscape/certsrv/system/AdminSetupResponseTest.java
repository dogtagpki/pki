package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AdminSetupResponseTest {

    private static AdminSetupResponse before = new AdminSetupResponse();

    @Before
    public void setUpBefore() {
        before.setAdminCert(new SystemCertData());
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AdminSetupResponse afterJSON = JSONSerializer.fromJSON(json, AdminSetupResponse.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
