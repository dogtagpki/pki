package com.netscape.certsrv.tps.token;

import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.tps.token.TokenData.TokenStatusData;

public class TokenDataTest {

    private static TokenData before = new TokenData();
    private static TokenStatusData statusData = new TokenStatusData();

    @Before
    public void setUpBefore() {
        before.setID("token1");
        before.setUserID("user1");
        before.setType("userKey");

        statusData.name = TokenStatus.ACTIVE;
        before.setStatus(statusData);

        before.setAppletID("APPLET1234");
        before.setKeyInfo("key info");
        before.setPolicy("FORCE_FORMAT=YES");
        before.setCreateTimestamp(new Date());
        before.setModifyTimestamp(new Date());
    }

    @Test
    public void testXML() throws Exception {
        // Act
        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        TokenData afterXML = TokenData.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        // Assert
        Assert.assertEquals(before, afterXML);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TokenData afterJSON = TokenData.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
