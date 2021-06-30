package com.netscape.certsrv.cert;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

public class CertDataInfoTest {

    private static CertDataInfo before = new CertDataInfo();

    @Before
    public void setUpBefore() {
        before.setID(new CertId("12512514865863765114"));
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setStatus("VALID");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertDataInfo afterJSON = JSONSerializer.fromJSON(json, CertDataInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
