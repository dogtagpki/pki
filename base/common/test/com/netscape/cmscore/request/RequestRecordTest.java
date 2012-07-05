package com.netscape.cmscore.request;

import java.util.Hashtable;

import junit.framework.Test;
import junit.framework.TestSuite;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBDynAttrMapper;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.dbs.DBRegistryDefaultStub;
import com.netscape.cmscore.dbs.DBSubsystemDefaultStub;
import com.netscape.cmscore.test.CMSBaseTestCase;
import com.netscape.cmscore.test.TestHelper;

public class RequestRecordTest extends CMSBaseTestCase {

    RequestRecord requestRecord;
    Request request;

    public RequestRecordTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        requestRecord = new RequestRecord();
        request = new Request(new RequestId("0xabcdef"));
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(RequestRecordTest.class);
    }

    public void testGetExtData() {
        Hashtable<String, Object> hash = new Hashtable<String, Object>();

        assertNotSame(hash, requestRecord.get(IRequestRecord.ATTR_EXT_DATA));
        requestRecord.mExtData = hash;
        assertSame(hash, requestRecord.get(IRequestRecord.ATTR_EXT_DATA));
    }

    public void testSetExtData() {
        Hashtable<String, Object> hash = new Hashtable<String, Object>();

        assertNotSame(requestRecord.mExtData, hash);
        requestRecord.set(IRequestRecord.ATTR_EXT_DATA, hash);
        assertSame(requestRecord.mExtData, hash);
    }

    public void testGetElements() {
        assertTrue(TestHelper.enumerationContains(requestRecord.getElements(),
                           IRequestRecord.ATTR_EXT_DATA));
    }

    public void testAddExtData() throws EBaseException {
        request.setExtData("foo", "bar");
        Hashtable<String, String> requestHashValue = new Hashtable<String, String>();
        requestHashValue.put("red", "rum");
        requestHashValue.put("blue", "gin");
        request.setExtData("hashkey", requestHashValue);

        requestRecord.add(request);

        assertEquals(request.mExtData, requestRecord.mExtData);
        assertNotSame(request.mExtData, requestRecord.mExtData);
    }

    public void testReadExtData() throws EBaseException {
        Hashtable<String, Object> extData = new Hashtable<String, Object>();
        extData.put("foo", "bar");
        Hashtable<String, String> extDataHashValue = new Hashtable<String, String>();
        extDataHashValue.put("red", "rum");
        extDataHashValue.put("blue", "gin");
        extData.put("hashkey", extDataHashValue);
        requestRecord.set(IRequestRecord.ATTR_EXT_DATA, extData);
        requestRecord.mRequestType = "foo";

        requestRecord.read(new RequestModDefaultStub(), request);

        // the request stores other attributes inside its mExtData when some
        // of its setters are called, so we have to compare manually.
        assertEquals("bar", request.mExtData.get("foo"));
        assertEquals(extDataHashValue, request.mExtData.get("hashkey"));
        assertNotSame(requestRecord.mExtData, request.mExtData);
    }

    public void testModExtData() throws EBaseException {
        ModificationSetStub mods = new ModificationSetStub();
        request.setExtData("foo", "bar");

        RequestRecord.mod(mods, request);

        assertTrue(mods.addCalledWithExtData);
        assertEquals(mods.addExtDataObject, request.mExtData);
    }

    public void testRegister() throws EDBException {
        DBSubsystemStub db = new DBSubsystemStub();

        RequestRecord.register(db);

        assertTrue(db.registry.registerCalledWithExtAttr);
        assertTrue(db.registry.extAttrMapper instanceof ExtAttrDynMapper);

        assertTrue(db.registry.registerObjectClassCalled);
        assertTrue(TestHelper.contains(db.registry.registerObjectClassLdapNames,
                                       "extensibleObject"));

        assertTrue(db.registry.registerDynamicMapperCalled);
        assertTrue(db.registry.dynamicMapper instanceof ExtAttrDynMapper);
    }

    class ModificationSetStub extends ModificationSet {
        public boolean addCalledWithExtData = false;
        public Object addExtDataObject = null;

        public void add(String name, int op, Object value) {
            if (IRequestRecord.ATTR_EXT_DATA.equals(name)) {
                addCalledWithExtData = true;
                addExtDataObject = value;
            }
        }
    }

    class DBSubsystemStub extends DBSubsystemDefaultStub {
        DBRegistryStub registry = new DBRegistryStub();

        public IDBRegistry getRegistry() {
            return registry;
        }
    }

    static class DBRegistryStub extends DBRegistryDefaultStub {
        boolean registerCalledWithExtAttr = false;
        IDBAttrMapper extAttrMapper = null;

        boolean registerObjectClassCalled = false;
        String[] registerObjectClassLdapNames = null;

        private boolean registerDynamicMapperCalled = false;
        private IDBDynAttrMapper dynamicMapper;

        public void registerObjectClass(String className, String ldapNames[]) throws EDBException {
            registerObjectClassCalled = true;
            registerObjectClassLdapNames = ldapNames;
        }

        public void registerAttribute(String ufName, IDBAttrMapper mapper) throws EDBException {
            if (IRequestRecord.ATTR_EXT_DATA.equals(ufName)) {
                registerCalledWithExtAttr = true;
                extAttrMapper = mapper;
            }
        }

        public void registerDynamicMapper(IDBDynAttrMapper mapper) {
            registerDynamicMapperCalled = true;
            dynamicMapper = mapper;
        }
    }
}
