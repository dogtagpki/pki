package com.netscape.certsrv.tps.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Date;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.tps.token.TokenData.TokenStatusData;
import com.netscape.certsrv.util.JSONSerializer;

public class TokenDataTest {

    private static TokenData before = new TokenData();
    private static TokenStatusData statusData = new TokenStatusData();

    @BeforeAll
    public static void setUpBefore() {
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
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TokenData afterJSON = JSONSerializer.fromJSON(json, TokenData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
