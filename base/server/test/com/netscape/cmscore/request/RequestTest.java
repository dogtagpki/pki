package com.netscape.cmscore.request;

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestSuite;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.app.CMSEngineDefaultStub;
import com.netscape.cmscore.test.CMSBaseTestCase;
import com.netscape.cmscore.test.TestHelper;

public class RequestTest extends CMSBaseTestCase {

    Request request;
    CMSMemoryStub cmsStub;

    public RequestTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        // this is needed because of CMS.AtoB/BtoA calls
        cmsStub = new CMSMemoryStub();
        CMS.setCMSEngine(cmsStub);

        request = new Request(new RequestId("0xabcdef"));
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(RequestTest.class);
    }

    public void testIsValidKey() {
        assertTrue(request.isValidExtDataKey("foo"));
        assertTrue(request.isValidExtDataKey("BARBAZ"));
        assertTrue(request.isValidExtDataKey("1122"));
        assertTrue(request.isValidExtDataKey("-"));
        assertTrue(request.isValidExtDataKey("1a-22"));
        assertTrue(request.isValidExtDataKey("a;b"));
        assertTrue(request.isValidExtDataKey("_"));
        assertTrue(request.isValidExtDataKey("this.is.encoded"));
        assertTrue(request.isValidExtDataKey("spaces are too"));

        assertFalse(request.isValidExtDataKey(null));
        assertFalse(request.isValidExtDataKey(""));
    }

    public void testIsSimpleExtDataValue() {
        request.mExtData.put("simple1", "foo");
        request.mExtData.put("complex1", new Hashtable<String, Object>());

        assertTrue(request.isSimpleExtDataValue("simple1"));
        assertFalse(request.isSimpleExtDataValue("complex1"));
        assertFalse(request.isSimpleExtDataValue("doesn't exist"));
    }

    public void testSetExtStringData() {
        request.setExtData("foo", "bar");
        request.setExtData("foo2", "bar2");
        assertEquals("bar", request.mExtData.get("foo"));
        assertEquals("bar2", request.mExtData.get("foo2"));

        request.setExtData("foo", "newvalue");
        assertEquals("newvalue", request.mExtData.get("foo"));

        request.setExtData("UPPER", "CASE");
        assertEquals("CASE", request.mExtData.get("upper"));

        assertFalse(request.setExtData("key", (String) null));
    }

    public void testVerifyValidExtDataHashtable() {
        Hashtable<String, String> valueHash = new Hashtable<String, String>();

        valueHash.put("key1", "val1");
        valueHash.put("key;2", "val2");
        assertTrue(request.isValidExtDataHashtableValue(valueHash));

        valueHash.clear();
        valueHash.put("", "bar");
        assertFalse(request.isValidExtDataHashtableValue(valueHash));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void testSetExtHashtableData() {
        Hashtable<String, String> valueHash = new Hashtable<String, String>();

        valueHash.put("key1", "val1");
        valueHash.put("KEY2", "val2");

        request.setExtData("TOPKEY", valueHash);

        Hashtable<String, String> out = request.getExtDataInHashtable("topkey");
        assertNotNull(out);

        assertTrue(out.containsKey("key1"));
        assertEquals("val1", out.get("key1"));

        assertTrue(out.containsKey("key2"));
        assertEquals("val2", out.get("key2"));

        valueHash.put("", "value");
        assertFalse(request.setExtData("topkey2", valueHash));

        assertFalse(request.setExtData("topkey3", (Hashtable) null));
    }

    public void testGetExtDataInString() {
        request.mExtData.put("strkey", "strval");
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        hashValue.put("uh", "oh");
        request.mExtData.put("hashkey", hashValue);

        assertEquals("strval", request.getExtDataInString("strkey"));
        assertEquals("strval", request.getExtDataInString("STRKEY"));
        assertEquals(null, request.getExtDataInString("notfound"));

        assertNull(request.getExtDataInString("hashkey"));
    }

    public void testGetExtDataInHashtable() {
        request.mExtData.put("strkey", "strval");
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        hashValue.put("uh", "oh");
        request.mExtData.put("hashkey", hashValue);

        Hashtable<String, String> out = request.getExtDataInHashtable("HASHKEY");
        assertNotNull(out);
        assertNull(request.getExtDataInHashtable("notfound"));
        assertNull(request.getExtDataInHashtable("strkey"));

        // Check the bevaiour of the returned hash
        assertEquals("oh", out.get("UH"));

        // check that we can't change the ExtData by altering the Hashtable
        hashValue = request.getExtDataInHashtable("hashkey");
        hashValue.put("newhashkey", "newhashvalue");
        hashValue = request.getExtDataInHashtable("hashkey");
        assertFalse(hashValue.containsKey("newhashkey"));
    }

    public void testGetExtDataKeys() {
        request.setExtData("FOO", "val1");
        request.setExtData("bar", new Hashtable<String, String>());

        assertTrue(TestHelper.enumerationContains(request.getExtDataKeys(), "foo"));
        assertTrue(TestHelper.enumerationContains(request.getExtDataKeys(), "bar"));
    }

    public void testSetExtDataSubkeyValue() {
        // creates hashtable first time
        assertNull(request.getExtDataInHashtable("topkey"));
        request.setExtData("TOPKEY", "SUBKEY", "value");
        Hashtable<String, String> value = request.getExtDataInHashtable("topkey");
        assertNotNull(value);
        assertTrue(value.containsKey("subkey"));
        assertEquals("value", value.get("subkey"));

        // adds to existing hashtable
        assertNull(request.getExtDataInHashtable("topkey2"));
        value = new Hashtable<String, String>();
        value.put("subkey2", "value2");
        request.setExtData("topkey2", value);
        request.setExtData("TOPKEY2", "subkey3", "value3");
        value = request.getExtDataInHashtable("topkey2");
        assertNotNull(value);
        assertTrue(value.containsKey("subkey2"));
        assertTrue(value.containsKey("subkey3"));
        assertEquals("value3", value.get("subkey3"));

        // can't sneak a bad topkey or subkey in this way
        assertFalse(request.setExtData("", "value", "value"));
        assertNull(request.getExtDataInHashtable(""));

        assertFalse(request.setExtData("key", "", "value"));
        assertNull(request.getExtDataInHashtable("key"));

        // can't sneak into an existing hashtable
        // this key was added above
        assertFalse(request.setExtData("topkey", "", "value"));
        value = request.getExtDataInHashtable("topkey");
        assertNotNull(value);
        assertFalse(value.containsKey(""));

        // Illegal values
        assertFalse(request.setExtData((String) null, "b", "c"));
        assertFalse(request.setExtData("a", (String) null, "c"));
        assertFalse(request.setExtData("a", "b", (String) null));
    }

    public void testGetExtDataSubkeyValue() {
        Hashtable<String, String> value = new Hashtable<String, String>();
        value.put("subkey", "value");

        request.setExtData("topkey", value);

        assertEquals("value", request.getExtDataInString("topkey", "SUBKEY"));
        assertNull(request.getExtDataInString("badkey", "subkey"));
        assertNull(request.getExtDataInString("topkey", "badkey"));
    }

    public void testGetSetExtDataInteger() {
        request.setExtData("foo", new Integer(234));

        assertNotNull(request.mExtData.get("foo"));
        assertEquals("234", request.mExtData.get("foo"));

        assertEquals(new Integer(234),
                request.getExtDataInInteger("foo"));

        request.setExtData("strkey", "bar");
        assertNull(request.getExtDataInInteger("strkey"));
        assertNull(request.getExtDataInInteger("notfound"));

        assertFalse(request.setExtData("key", (Integer) null));
    }

    public void testGetSetExtDataIntegerArray() throws Exception {
        Integer[] data = new Integer[] {
                Integer.valueOf(5),
                Integer.valueOf(23),
                Integer.valueOf(12)
        };
        assertTrue(request.setExtData("topkey1", data));
        Integer[] retval = request.getExtDataInIntegerArray("topkey1");
        assertNotNull(retval);
        assertEquals(3, retval.length);
        assertEquals(data[0], retval[0]);
        assertEquals(data[1], retval[1]);
        assertEquals(data[2], retval[2]);

        // invalid conversion
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        hashValue.put("0", "5");
        hashValue.put("1", "bar");
        request.setExtData("topkey2", hashValue);
        assertNull(request.getExtDataInIntegerArray("topkey2"));

        assertFalse(request.setExtData("key", (Integer[]) null));
    }

    public void testGetSetExtDataBigInteger() {
        request.setExtData("foo", new BigInteger("234234234234"));

        assertNotNull(request.mExtData.get("foo"));
        assertEquals("234234234234", request.mExtData.get("foo"));

        assertEquals(new BigInteger("234234234234"),
                request.getExtDataInBigInteger("foo"));

        request.setExtData("strkey", "bar");
        assertNull(request.getExtDataInBigInteger("strkey"));
        assertNull(request.getExtDataInBigInteger("notfound"));

        assertFalse(request.setExtData("key", (BigInteger) null));
    }

    public void testGetSetExtDataBigIntegerArray() throws Exception {
        BigInteger[] data = new BigInteger[] {
                new BigInteger("111111111"),
                new BigInteger("222222222"),
                new BigInteger("333333333")
        };
        assertTrue(request.setExtData("topkey1", data));
        BigInteger[] retval = request.getExtDataInBigIntegerArray("topkey1");
        assertNotNull(retval);
        assertEquals(3, retval.length);
        assertEquals(data[0], retval[0]);
        assertEquals(data[1], retval[1]);
        assertEquals(data[2], retval[2]);

        // invalid conversion
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        hashValue.put("0", "5");
        hashValue.put("1", "bar");
        request.setExtData("topkey2", hashValue);
        assertNull(request.getExtDataInBigIntegerArray("topkey2"));

        assertFalse(request.setExtData("key", (BigInteger[]) null));
    }

    public void testSetExtDataThrowable() {
        EBaseException e = new EBaseException("This is an error");

        request.setExtData("key", e);

        assertEquals(e.toString(), request.mExtData.get("key"));

        assertFalse(request.setExtData("key", (Throwable) null));
    }

    public void testGetSetByteArray() {
        byte[] data = new byte[] { 112, 96, 0, -12 };

        assertFalse(cmsStub.bToACalled);
        request.setExtData("key", data);
        assertTrue(cmsStub.bToACalled);
        assertEquals(data, cmsStub.bToACalledWith);

        assertFalse(cmsStub.aToBCalled);
        byte[] out = request.getExtDataInByteArray("key");
        assertTrue(cmsStub.aToBCalled);
        assertEquals(data, out);

        assertFalse(request.setExtData("key", (byte[]) null));
    }

    public void testGetSetCert() throws CertificateException {
        X509CertImpl cert = getFakeCert();

        assertFalse(cmsStub.bToACalled);
        assertTrue(request.setExtData("key", cert));
        assertTrue(cmsStub.bToACalled);

        assertFalse(cmsStub.aToBCalled);
        X509CertImpl retval = request.getExtDataInCert("key");
        assertTrue(cmsStub.aToBCalled);
        assertEquals(cert, retval);

        assertFalse(request.setExtData("key", (X509CertImpl) null));
    }

    public void testGetSetCertArray() throws Exception {
        // this test is also pretty weak, but fortunately relies on the
        // building blocks.
        X509CertImpl[] vals = new X509CertImpl[] {
                getFakeCert(),
                getFakeCert()
        };

        assertTrue(request.setExtData("key", vals));
        Hashtable<?, ?> hashVals = (Hashtable<?, ?>) request.mExtData.get("key");
        assertEquals(2, hashVals.keySet().size());

        assertFalse(cmsStub.aToBCalled);
        X509CertImpl[] retval = request.getExtDataInCertArray("key");
        assertNotNull(retval);
        assertTrue(cmsStub.aToBCalled);

        assertEquals(2, retval.length);
        assertEquals(vals[0], retval[0]);
        assertEquals(vals[1], retval[1]);

        assertFalse(request.setExtData("key", (X509CertImpl[]) null));
    }

    public void testGetSetStringArray() throws Exception {
        String[] value = new String[] { "blue", "green", "red", "orange" };
        assertTrue(request.setExtData("key", value));

        assertTrue(request.mExtData.containsKey("key"));
        @SuppressWarnings("unchecked")
        Hashtable<String, String> hashValue = (Hashtable<String, String>) request.mExtData.get("key");
        assertTrue(hashValue.containsKey("0"));
        assertTrue(hashValue.containsKey("1"));
        assertTrue(hashValue.containsKey("2"));
        assertTrue(hashValue.containsKey("3"));
        assertEquals("blue", hashValue.get("0"));
        assertEquals("green", hashValue.get("1"));
        assertEquals("red", hashValue.get("2"));
        assertEquals("orange", hashValue.get("3"));

        String[] retval = request.getExtDataInStringArray("key");
        assertNotNull(retval);
        assertEquals(4, retval.length);
        assertEquals("blue", retval[0]);
        assertEquals("green", retval[1]);
        assertEquals("red", retval[2]);
        assertEquals("orange", retval[3]);

        // Try with sparse input
        hashValue = new Hashtable<String, String>();
        hashValue.put("0", "square");
        hashValue.put("4", "triangle");
        hashValue.put("6", "octogon");
        request.setExtData("kevin", hashValue);

        retval = request.getExtDataInStringArray("kevin");
        assertNotNull(retval);
        assertEquals(7, retval.length);
        assertEquals("square", retval[0]);
        assertNull(retval[1]);
        assertNull(retval[2]);
        assertNull(retval[3]);
        assertEquals("triangle", retval[4]);
        assertNull(retval[5]);
        assertEquals("octogon", retval[6]);

        // invalid conversion
        hashValue = new Hashtable<String, String>();
        hashValue.put("0", "foo");
        hashValue.put("badkey", "bar");
        request.setExtData("cory", hashValue);
        assertNull(request.getExtDataInStringArray("cory"));

        assertFalse(request.setExtData("key", (String[]) null));

    }

    public void testGetSetStringVector() {
        Vector<String> stringVector = new Vector<String>();
        stringVector.add("blue");
        stringVector.add("green");
        stringVector.add("red");
        stringVector.add("orange");

        assertTrue(request.setExtData("key", stringVector));

        assertTrue(request.mExtData.containsKey("key"));
        @SuppressWarnings("unchecked")
        Hashtable<String, String> hashValue = (Hashtable<String, String>) request.mExtData.get("key");
        assertTrue(hashValue.containsKey("0"));
        assertTrue(hashValue.containsKey("1"));
        assertTrue(hashValue.containsKey("2"));
        assertTrue(hashValue.containsKey("3"));
        assertEquals("blue", hashValue.get("0"));
        assertEquals("green", hashValue.get("1"));
        assertEquals("red", hashValue.get("2"));
        assertEquals("orange", hashValue.get("3"));

        Vector<String> retval = request.getExtDataInStringVector("key");
        assertEquals(4, retval.size());
        assertEquals("blue", retval.elementAt(0));
        assertEquals("green", retval.elementAt(1));
        assertEquals("red", retval.elementAt(2));
        assertEquals("orange", retval.elementAt(3));

        // invalid conversion
        hashValue = new Hashtable<String, String>();
        hashValue.put("0", "foo");
        hashValue.put("badkey", "bar");
        request.setExtData("cory", hashValue);
        assertNull(request.getExtDataInStringVector("cory"));

        assertFalse(request.setExtData("key", (Vector<?>) null));
    }

    public void testGetSetCertInfo() {
        X509CertInfoStub cert = new X509CertInfoStub();

        assertFalse(cmsStub.bToACalled);
        assertFalse(cert.getEncodedCalled);
        assertTrue(request.setExtData("key", cert));
        assertTrue(cmsStub.bToACalled);
        assertTrue(cert.getEncodedCalled);

        // this is a pretty weak test, but it's hard to assert much here
        assertFalse(cmsStub.aToBCalled);
        request.getExtDataInCertInfo("key");
        assertTrue(cmsStub.aToBCalled);

        assertFalse(request.setExtData("key", (X509CertInfo) null));
    }

    public void testGetSetCertInfoArray() {
        X509CertInfo[] vals = new X509CertInfoStub[] {
                new X509CertInfoStub(),
                new X509CertInfoStub()
        };

        assertTrue(request.setExtData("key", vals));
        Hashtable<?, ?> hashVals = (Hashtable<?, ?>) request.mExtData.get("key");
        assertEquals(2, hashVals.keySet().size());

        assertFalse(cmsStub.aToBCalled);
        request.getExtDataInCertInfoArray("key");
        assertTrue(cmsStub.aToBCalled);

        assertFalse(request.setExtData("key", (X509CertInfo[]) null));
    }

    public void testGetBoolean() {
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        hashValue.put("one", "false");
        hashValue.put("two", "true");
        hashValue.put("three", "on");
        hashValue.put("four", "off");
        request.mExtData.put("hashkey", hashValue);

        assertFalse(request.getExtDataInBoolean("hashkey", "one", true));
        assertTrue(request.getExtDataInBoolean("hashkey", "two", false));
        assertTrue(request.getExtDataInBoolean("hashkey", "three", false));
        assertFalse(request.getExtDataInBoolean("hashkey", "four", true));

        assertTrue(request.getExtDataInBoolean("notfound", "nope", true));
        assertTrue(request.getExtDataInBoolean("hashkey", "notfound", true));

        assertFalse(request.getExtDataInBoolean("notfound", "nope", false));
        assertFalse(request.getExtDataInBoolean("hashkey", "notfound", false));

        request.mExtData.put("one", "false");
        request.mExtData.put("two", "true");
        request.mExtData.put("three", "on");
        request.mExtData.put("four", "off");

        assertFalse(request.getExtDataInBoolean("one", true));
        assertTrue(request.getExtDataInBoolean("two", false));
        assertTrue(request.getExtDataInBoolean("three", false));
        assertFalse(request.getExtDataInBoolean("four", true));

        assertTrue(request.getExtDataInBoolean("notfound", true));
        assertFalse(request.getExtDataInBoolean("notfound", false));
    }

    public void testGetSetRevokedCertArray() {
        RevokedCertImpl[] vals = new RevokedCertImplStub[] {
                new RevokedCertImplStub(),
                new RevokedCertImplStub()
        };

        assertTrue(request.setExtData("key", vals));
        Hashtable<?, ?> hashVals = (Hashtable<?, ?>) request.mExtData.get("key");
        assertEquals(2, hashVals.keySet().size());

        assertFalse(cmsStub.aToBCalled);
        request.getExtDataInCertInfoArray("key");
        assertTrue(cmsStub.aToBCalled);

        assertFalse(request.setExtData("key", (RevokedCertImpl[]) null));
    }

    public void testGetSetCertExts() throws Exception {
        CertificateExtensions exts = new CertificateExtensions();
        BasicConstraintsExtension ext = new BasicConstraintsExtension(false, 1);

        // check if empty CertificateExtensions work
        assertTrue(request.setExtData("key", exts));
        CertificateExtensions retval = request.getExtDataInCertExts("key");
        assertNotNull(retval);
        assertEquals(0, retval.size());

        exts.set(PKIXExtensions.BasicConstraints_Id.toString(), ext);
        assertTrue(request.setExtData("key2", exts));
        assertTrue(request.mExtData.containsKey("key2"));

        retval = request.getExtDataInCertExts("key2");
        assertNotNull(retval);
        assertEquals(1, retval.size());

        assertFalse(request.setExtData("key", (CertificateExtensions) null));
    }

    public void testGetSetCertSubjectName() throws Exception {
        CertificateSubjectName name = new CertificateSubjectName(
                new X500Name("cn=kevin"));
        assertTrue(request.setExtData("key", name));
        assertTrue(request.mExtData.containsKey("key"));

        CertificateSubjectName retval = request.getExtDataInCertSubjectName("key");
        assertNotNull(retval);
        // the 'CN=' is uppercased at some point
        assertEquals("cn=kevin",
                retval.get(CertificateSubjectName.DN_NAME).toString().toLowerCase());

        assertFalse(request.setExtData("key", (CertificateSubjectName) null));
    }

    public void testGetSetAuthToken() {
        AuthToken token = new AuthToken(null);
        token.set("key1", "val1");
        token.set("key2", "val2");
        token.set("key3", Integer.valueOf(5));

        assertTrue(request.setExtData("key", token));

        IAuthToken retval = request.getExtDataInAuthToken("key");
        assertNotNull(retval);

        assertEquals(token.getInString("key1"), retval.getInString("key1"));
        assertEquals(token.getInString("key2"), retval.getInString("key2"));
        assertEquals(token.getInInteger("key3"), retval.getInInteger("key3"));

        assertFalse(request.setExtData("key", (AuthToken) null));
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

    class X509CertInfoStub extends X509CertInfo {
        /**
         *
         */
        private static final long serialVersionUID = -821992386369710423L;
        boolean getEncodedCalled = false;

        public X509CertInfoStub() {
        }

        public byte[] getEncodedInfo(boolean ignoreCache) throws CertificateEncodingException {
            getEncodedCalled = true;
            return new byte[] {};
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result + getOuterType().hashCode();
            result = prime * result + (getEncodedCalled ? 1231 : 1237);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (!super.equals(obj))
                return false;
            if (getClass() != obj.getClass())
                return false;
            X509CertInfoStub other = (X509CertInfoStub) obj;
            if (!getOuterType().equals(other.getOuterType()))
                return false;
            if (getEncodedCalled != other.getEncodedCalled)
                return false;
            return true;
        }

        private RequestTest getOuterType() {
            return RequestTest.this;
        }

    }

    static class RevokedCertImplStub extends RevokedCertImpl {
        /**
         *
         */
        private static final long serialVersionUID = -9088436260566619005L;
        boolean getEncodedCalled = false;

        public byte[] getEncoded() throws CRLException {
            getEncodedCalled = true;
            return new byte[] {};
        }
    }

}
