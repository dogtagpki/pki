package com.netscape.certsrv.tps.cert;

import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TPSCertDataTest {

    private static TPSCertData before = new TPSCertData();

    @Before
    public void setUpBefore() {
        before.setID("cert1");
        before.setSerialNumber("16");
        before.setSubject("cn=someone");
        before.setTokenID("TOKEN1234");
        before.setKeyType("something");
        before.setStatus("active");
        before.setUserID("user1");
        before.setCreateTime(new Date());
        before.setModifyTime(new Date());
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TPSCertData afterJSON = TPSCertData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
