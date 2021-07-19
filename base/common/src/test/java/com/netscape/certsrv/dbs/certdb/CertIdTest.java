package com.netscape.certsrv.dbs.certdb;

import org.junit.Assert;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;

public class CertIdTest {

    private static CertId before = new CertId(3);

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CertId afterJSON = JSONSerializer.fromJSON(json, CertId.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
