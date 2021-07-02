package com.netscape.certsrv.tps.token;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class TokenStatusTest {

    private static TokenStatus before = TokenStatus.DAMAGED;

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TokenStatus afterJSON = JSONSerializer.fromJSON(json, TokenStatus.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
