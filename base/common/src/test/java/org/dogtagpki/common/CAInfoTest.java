package org.dogtagpki.common;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.util.JSONSerializer;


public class CAInfoTest {

    private static CAInfo before = new CAInfo();

    @Before
    public void setUpBefore() {
        before.setArchivalMechanism(CAInfo.KEYWRAP_MECHANISM);
        before.setEncryptAlgorithm(CAInfo.ENCRYPT_MECHANISM);
        before.setKeyWrapAlgorithm(CAInfo.KEYWRAP_MECHANISM);
        before.setRsaPublicKeyWrapAlgorithm(CAInfo.RSA_PUBLIC_KEY_WRAP);
        before.setCaRsaPublicKeyWrapAlgorithm(CAInfo.RSA_PUBLIC_KEY_WRAP);
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CAInfo afterJSON = JSONSerializer.fromJSON(json, CAInfo.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }
}
