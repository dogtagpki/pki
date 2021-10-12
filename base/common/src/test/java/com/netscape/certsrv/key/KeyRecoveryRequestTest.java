package com.netscape.certsrv.key;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRecoveryRequestTest {

    private static KeyRecoveryRequest before = new KeyRecoveryRequest();

    @Before
    public void setUpBefore() {
        before.setClassName(KeyRecoveryRequest.class.getName());
        before.setKeyId(new KeyId("0x123456"));
        before.setNonceData("nonce-XXX12345");
        before.setPassphrase("password");
        before.setRequestId(new RequestId("0x123F"));
        before.setCertificate("123ABCAAAA");
        before.setSessionWrappedPassphrase("XXXXXXXX1234");
        before.setTransWrappedSessionKey("124355AAA");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRecoveryRequest afterJSON = JSONSerializer.fromJSON(json, KeyRecoveryRequest.class);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
