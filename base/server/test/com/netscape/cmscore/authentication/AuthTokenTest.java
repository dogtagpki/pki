package com.netscape.cmscore.authentication;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import junit.framework.Test;
import junit.framework.TestSuite;
import netscape.security.util.DerOutputStream;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.cmscore.app.CMSEngineDefaultStub;
import com.netscape.cmscore.test.CMSBaseTestCase;

public class AuthTokenTest extends CMSBaseTestCase {

    AuthToken authToken;
    CMSMemoryStub cmsStub;

    public AuthTokenTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        authToken = new AuthToken(null);

        // this is needed because of CMS.AtoB/BtoA calls
        cmsStub = new CMSMemoryStub();
        CMS.setCMSEngine(cmsStub);
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(AuthTokenTest.class);
    }

    public void testGetSetString() {
        authToken.set("key", "value");
        assertEquals("value", authToken.get("key"));
        assertEquals("value", authToken.getInString("key"));

        assertFalse(authToken.set("key", (String) null));
    }

    public void testGetSetByteArray() {
        byte[] data = new byte[] { -12, 0, 14, 15 };

        assertFalse(cmsStub.bToACalled);
        authToken.set("key", data);
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        byte[] retval = authToken.getInByteArray("key");
        assertEquals(data, retval);

        assertFalse(authToken.set("key2", (byte[]) null));
    }

    public void testGetSetInteger() {
        authToken.set("key", Integer.valueOf(432));
        assertEquals("432", authToken.get("key"));
        assertEquals(Integer.valueOf(432), authToken.getInInteger("key"));

        assertNull(authToken.getInInteger("notfound"));

        authToken.set("key2", "value");
        assertNull(authToken.getInInteger("key2"));

        assertFalse(authToken.set("key3", (Integer) null));
    }

    public void testGetSetBigIntegerArray() {
        BigInteger[] data = new BigInteger[] {
                new BigInteger("111111111"),
                new BigInteger("222222222"),
                new BigInteger("333333333")
        };
        authToken.set("key", data);
        assertEquals("111111111,222222222,333333333",
                authToken.get("key"));
        BigInteger[] retval = authToken.getInBigIntegerArray("key");
        assertEquals(3, retval.length);
        assertEquals(data[0], retval[0]);
        assertEquals(data[1], retval[1]);
        assertEquals(data[2], retval[2]);

        authToken.set("key2", "123456");
        retval = authToken.getInBigIntegerArray("key2");
        assertEquals(1, retval.length);
        assertEquals(new BigInteger("123456"), retval[0]);

        authToken.set("key3", "oops");
        assertNull(authToken.getInBigIntegerArray("key3"));

        // corner case test
        authToken.set("key", ",");
        retval = authToken.getInBigIntegerArray("key");
        assertNull(retval);

        assertFalse(authToken.set("key4", (BigInteger[]) null));
    }

    public void testGetSetDate() throws Exception {
        Date value = new Date();
        authToken.set("key", value);
        assertEquals(String.valueOf(value.getTime()),
                authToken.get("key"));
        assertEquals(value, authToken.getInDate("key"));

        authToken.set("key2", "234567");
        Date retval = authToken.getInDate("key2");
        if (retval == null) {
            throw new Exception("Unable to get key2 as Date");
        }
        assertEquals(234567L, retval.getTime());

        authToken.set("key3", "oops");
        assertNull(authToken.getInDate("key3"));

        assertFalse(authToken.set("key4", (Date) null));
    }

    public void testGetSetStringArray() throws IOException {
        String[] value = new String[] {
                "eenie", "meenie", "miny", "moe"
        };

        assertFalse(cmsStub.bToACalled);
        authToken.set("key", value);
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        String[] retval = authToken.getInStringArray("key");
        if (retval == null) {
            throw new IOException("Unable to get key as String Array");
        }
        assertTrue(cmsStub.aToBCalled);
        assertEquals(4, retval.length);
        assertEquals(value[0], retval[0]);
        assertEquals(value[1], retval[1]);
        assertEquals(value[2], retval[2]);
        assertEquals(value[3], retval[3]);

        // illegal value parsing
        authToken.set("key2", new byte[] { 1, 2, 3, 4 });
        assertNull(authToken.getInStringArray("key2"));

        try (DerOutputStream out = new DerOutputStream()) {
            out.putPrintableString("testing");
            authToken.set("key3", out.toByteArray());
        }

        assertNull(authToken.getInStringArray("key3"));

        assertFalse(authToken.set("key4", (String[]) null));
    }

    public void testGetSetCert() throws CertificateException {
        X509CertImpl cert = getFakeCert();

        assertFalse(cmsStub.bToACalled);
        authToken.set("key", cert);
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        X509CertImpl retval = authToken.getInCert("key");
        assertTrue(cmsStub.aToBCalled);
        assertNotNull(retval);
        assertEquals(cert, retval);

        assertFalse(authToken.set("key2", (X509CertImpl) null));
    }

    public void testGetSetCertExts() throws IOException {
        CertificateExtensions certExts = new CertificateExtensions();
        BasicConstraintsExtension ext = new BasicConstraintsExtension(false, 1);

        assertTrue(authToken.set("key", certExts));
        assertNotNull(authToken.get("key"));
        CertificateExtensions retval = authToken.getInCertExts("key");
        assertNotNull(retval);
        assertEquals(0, retval.size());

        certExts.set(PKIXExtensions.BasicConstraints_Id.toString(), ext);
        assertTrue(authToken.set("key2", certExts));

        retval = authToken.getInCertExts("key2");
        assertNotNull(authToken.get("key2"));
        assertNotNull(retval);
        assertEquals(1, retval.size());

        assertFalse(authToken.set("key3", (CertificateExtensions) null));
    }

    public void testGetSetCertificates() throws CertificateException, IOException {
        X509CertImpl cert1 = getFakeCert();
        X509CertImpl cert2 = getFakeCert();
        X509CertImpl[] certArray = new X509CertImpl[] { cert1, cert2 };
        Certificates certs = new Certificates(certArray);

        assertFalse(cmsStub.bToACalled);
        authToken.set("key", certs);
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        Certificates retval = authToken.getInCertificates("key");
        assertTrue(cmsStub.aToBCalled);
        assertNotNull(retval);

        X509Certificate[] retCerts = retval.getCertificates();
        assertEquals(2, retCerts.length);
        assertEquals(cert1, retCerts[0]);
        assertEquals(cert2, retCerts[1]);

        assertFalse(authToken.set("key2", (Certificates) null));
    }

    public void testGetSetByteArrayArray() throws IOException {
        byte[][] value = new byte[][] {
                new byte[] { 1, 2, 3, 4 },
                new byte[] { 12, 13, 14 },
                new byte[] { 50, -12, 0, 100 }
        };

        assertFalse(cmsStub.bToACalled);
        assertTrue(authToken.set("key", value));
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        byte[][] retval = authToken.getInByteArrayArray("key");
        assertTrue(cmsStub.aToBCalled);
        assertNotNull(retval);
        assertEquals(value.length, retval.length);
        for (int i = 0; i < value.length; i++) {
            assertEquals(value[i].length, retval[i].length);
            for (int j = 0; j < value[i].length; j++) {
                assertEquals(value[i][j], retval[i][j]);
            }
        }

        assertFalse(authToken.set("key2", (byte[][]) null));
    }

    /**
     * CMSMemoryStub
     *
     * This class is used to help test methods that rely on setting and then
     * getting a value out. It assumes BtoA is always called first, stores
     * the value passed in, and then returns that value for BtoA.
     */
    static class CMSMemoryStub extends CMSEngineDefaultStub {
        boolean bToACalled = false;
        byte[] bToACalledWith = null;

        boolean aToBCalled = false;
        String aToBCalledWith = null;

        public String BtoA(byte data[]) {
            bToACalled = true;
            bToACalledWith = data;
            return "garbagetostoreinthehash";
        }

        public byte[] AtoB(String data) {
            aToBCalled = true;
            aToBCalledWith = data;
            return bToACalledWith;
        }
    }
}
