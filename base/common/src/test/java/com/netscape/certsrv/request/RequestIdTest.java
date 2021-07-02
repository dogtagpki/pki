package com.netscape.certsrv.request;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class RequestIdTest {

    private static RequestId before = new RequestId("1");

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        RequestId afterJSON = JSONSerializer.fromJSON(json, RequestId.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
