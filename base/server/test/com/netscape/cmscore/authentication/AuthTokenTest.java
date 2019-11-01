package com.netscape.cmscore.authentication;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.dogtagpki.server.authentication.AuthToken;
import org.junit.Assert;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.cmscore.test.CMSBaseTestCase;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AuthTokenTest extends CMSBaseTestCase {

    AuthToken authToken;

    public AuthTokenTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        authToken = new AuthToken(null);
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
        authToken.set("key", data);

        byte[] retval = authToken.getInByteArray("key");
        Assert.assertArrayEquals(data, retval);

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
        Assert.assertArrayEquals(data, retval);

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

        authToken.set("key", value);

        String[] retval = authToken.getInStringArray("key");
        if (retval == null) {
            throw new IOException("Unable to get key as String Array");
        }
        Assert.assertArrayEquals(value, retval);

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
        authToken.set("key", cert);

        X509CertImpl retval = authToken.getInCert("key");
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

        authToken.set("key", certs);

        Certificates retval = authToken.getInCertificates("key");
        assertNotNull(retval);

        X509Certificate[] retCerts = retval.getCertificates();
        Assert.assertArrayEquals(certArray, retCerts);

        assertFalse(authToken.set("key2", (Certificates) null));
    }

    public void testGetSetByteArrayArray() throws IOException {
        byte[][] value = new byte[][] {
                new byte[] { 1, 2, 3, 4 },
                new byte[] { 12, 13, 14 },
                new byte[] { 50, -12, 0, 100 }
        };

        assertTrue(authToken.set("key", value));

        byte[][] retval = authToken.getInByteArrayArray("key");
        assertNotNull(retval);
        Assert.assertArrayEquals(value, retval);

        assertFalse(authToken.set("key2", (byte[][]) null));
    }
}
