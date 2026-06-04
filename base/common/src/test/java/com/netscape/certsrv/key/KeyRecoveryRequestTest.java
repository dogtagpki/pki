package com.netscape.certsrv.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

public class KeyRecoveryRequestTest {

    public static Logger logger = LoggerFactory.getLogger(KeyRecoveryRequestTest.class);

    private static KeyRecoveryRequest before = new KeyRecoveryRequest();

    @BeforeAll
    public static void setUpBefore() {
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
        logger.debug("JSON (before): " + json);

        KeyRecoveryRequest afterJSON = JSONSerializer.fromJSON(json, KeyRecoveryRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
