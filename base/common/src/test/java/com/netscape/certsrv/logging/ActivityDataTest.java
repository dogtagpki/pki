package com.netscape.certsrv.logging;

import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class ActivityDataTest {

    private static ActivityData before = new ActivityData();

    @Before
    public void setUpBefore() {
        before.setID("activity1");
        before.setTokenID("TOKEN1234");
        before.setUserID("user1");
        before.setIP("192.168.1.1");
        before.setOperation("enroll");
        before.setResult("success");
        before.setMessage("test");
        before.setDate(new Date());
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        ActivityData afterJSON = JSONSerializer.fromJSON(json, ActivityData.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
