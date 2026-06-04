package com.netscape.certsrv.system;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.util.JSONSerializer;

public class CertificateSetupRequestTest {

    public static Logger logger = LoggerFactory.getLogger(CertificateSetupRequestTest.class);

    private static CertificateSetupRequest before = new CertificateSetupRequest();

    @BeforeAll
    public static void setUpBefore() throws MalformedURLException {
        before.setPin("bar");
        before.setSystemCert(new SystemCertData());
        before.setTag("lorem");
    }

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        logger.debug("JSON (before): " + json);

        CertificateSetupRequest afterJSON =
                JSONSerializer.fromJSON(json, CertificateSetupRequest.class);
        logger.debug("JSON (after): " + afterJSON.toJSON());

        // Assert
        assertEquals(before, afterJSON);
    }

}
