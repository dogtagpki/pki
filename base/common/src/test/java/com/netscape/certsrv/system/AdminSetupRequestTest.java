package com.netscape.certsrv.system;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class AdminSetupRequestTest {

    private static AdminSetupRequest before = new AdminSetupRequest();

    @Before
    public void setUpBefore() {
        before.setAdminCertRequest("foo");
        before.setAdminCertRequestType("bar");
        before.setAdminKeyType("lorem");
        before.setAdminProfileID("ipsum");
        before.setAdminSubjectDN("dolor");
        before.setInstallToken(new InstallToken("sit"));
        before.setPin("amet");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        AdminSetupRequest afterJSON = JSONSerializer.fromJSON(json, AdminSetupRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
