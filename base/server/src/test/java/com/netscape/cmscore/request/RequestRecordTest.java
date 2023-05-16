package com.netscape.cmscore.request;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Hashtable;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.dbs.DBRegistry;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.test.TestHelper;

public class RequestRecordTest {

    static RequestRecord requestRecord;
    static Request request;

    @BeforeAll
    public static void cmsTestSetUp() {
        requestRecord = new RequestRecord();
        request = new Request(new RequestId("0xabcdef"));
    }

    @Test
    public void testGetExtData() {
        Hashtable<String, Object> hash = new Hashtable<>();

        assertNotSame(hash, requestRecord.get(RequestRecord.ATTR_EXT_DATA));
        requestRecord.mExtData = hash;
        assertSame(hash, requestRecord.get(RequestRecord.ATTR_EXT_DATA));
    }

    @Test
    public void testSetExtData() {
        Hashtable<String, Object> hash = new Hashtable<>();

        assertNotSame(requestRecord.mExtData, hash);
        requestRecord.set(RequestRecord.ATTR_EXT_DATA, hash);
        assertSame(requestRecord.mExtData, hash);
    }

    @Test
    public void testGetElements() {
        assertTrue(TestHelper.enumerationContains(requestRecord.getElements(), RequestRecord.ATTR_EXT_DATA));
    }

    @Test
    public void testAddExtData() throws EBaseException {
        request.setExtData("foo", "bar");
        Hashtable<String, String> requestHashValue = new Hashtable<>();
        requestHashValue.put("red", "rum");
        requestHashValue.put("blue", "gin");
        request.setExtData("hashkey", requestHashValue);

        requestRecord.add(request);

        assertEquals(request.mExtData, requestRecord.mExtData);
        assertNotSame(request.mExtData, requestRecord.mExtData);
    }

    @Test
    public void testReadExtData() throws EBaseException {
        Hashtable<String, Object> extData = new Hashtable<>();
        extData.put("foo", "bar");
        Hashtable<String, String> extDataHashValue = new Hashtable<>();
        extDataHashValue.put("red", "rum");
        extDataHashValue.put("blue", "gin");
        extData.put("hashkey", extDataHashValue);
        requestRecord.set(RequestRecord.ATTR_EXT_DATA, extData);
        requestRecord.mRequestType = "foo";
        requestRecord.set(RequestRecord.ATTR_REQUEST_STATE, RequestStatus.BEGIN);

        requestRecord.read(request);

        // the request stores other attributes inside its mExtData when some
        // of its setters are called, so we have to compare manually.
        assertEquals("bar", request.mExtData.get("foo"));
        assertEquals(extDataHashValue, request.mExtData.get("hashkey"));
        assertNotSame(requestRecord.mExtData, request.mExtData);
    }

    @Test
    public void testModExtData() throws EBaseException {
        ModificationSetStub mods = new ModificationSetStub();
        request.setExtData("foo", "bar");

        RequestRecord.mod(mods, request);

        assertTrue(mods.addCalledWithExtData);
        assertEquals(mods.addExtDataObject, request.mExtData);
    }

    @Test
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

        @Override
        public void add(String name, int op, Object value) {
            if (RequestRecord.ATTR_EXT_DATA.equals(name)) {
                addCalledWithExtData = true;
                addExtDataObject = value;
            }
        }
    }

    class DBSubsystemStub extends DBSubsystem {
        DBRegistryStub registry = new DBRegistryStub();

        @Override
        public DBRegistry getRegistry() {
            return registry;
        }
    }

    static class DBRegistryStub extends DBRegistry {
        boolean registerCalledWithExtAttr = false;
        DBAttrMapper extAttrMapper = null;

        boolean registerObjectClassCalled = false;
        String[] registerObjectClassLdapNames = null;

        private boolean registerDynamicMapperCalled = false;
        private DBDynAttrMapper dynamicMapper;

        @Override
        public void registerObjectClass(String className, String ldapNames[]) throws EDBException {
            registerObjectClassCalled = true;
            registerObjectClassLdapNames = ldapNames;
        }

        @Override
        public void registerAttribute(String ufName, DBAttrMapper mapper) throws EDBException {
            if (RequestRecord.ATTR_EXT_DATA.equals(ufName)) {
                registerCalledWithExtAttr = true;
                extAttrMapper = mapper;
            }
        }

        @Override
        public void registerDynamicMapper(DBDynAttrMapper mapper) {
            registerDynamicMapperCalled = true;
            dynamicMapper = mapper;
        }
    }
}
