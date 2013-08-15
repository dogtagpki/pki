package com.netscape.cmscore.test;

import java.security.cert.CertificateException;

import junit.framework.TestCase;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSSession;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.app.CMSEngineDefaultStub;
import com.netscape.cmscore.dbs.DBRegistryDefaultStub;
import com.netscape.cmscore.dbs.DBSSessionDefaultStub;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.DBSubsystemDefaultStub;
import com.netscape.cmscore.logging.LoggerDefaultStub;

/**
 * The base class for all CMS unit tests. This sets up some basic stubs
 * that allow unit tests to work without bumping into uninitialized subsystems
 * (like the CMS logging system).
 */
public abstract class CMSBaseTestCase extends TestCase {
    CMSEngineStub engine;
    LoggerDefaultStub logger;
    DBSubsystemStub db;
    DBRegistryDefaultStub registry;
    DBSSessionDefaultStub session;

    public CMSBaseTestCase(String name) {
        super(name);
    }

    public final void setUp() {
        engine = new CMSEngineStub();
        logger = new LoggerDefaultStub();
        db = new DBSubsystemStub();
        registry = new DBRegistryDefaultStub();
        session = new DBSSessionDefaultStub();

        CMS.setCMSEngine(engine);
        DBSubsystem.setInstance(db);

        cmsTestSetUp();
    }

    public final void tearDown() {
        cmsTestTearDown();
    }

    public abstract void cmsTestSetUp();

    public abstract void cmsTestTearDown();

    public X509CertImpl getFakeCert() throws CertificateException {
        byte[] certData = new byte[] {
                48, -126, 1, 18, 48, -127, -67, -96, 3, 2, 1, 2, 2, 1,
                1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 4,
                5, 0, 48, 18, 49, 16, 48, 14, 6, 3, 85, 4, 3, 19,
                7, 116, 101, 115, 116, 105, 110, 103, 48, 30, 23, 13, 48, 55,
                48, 55, 49, 50, 49, 55, 51, 56, 51, 52, 90, 23, 13, 48,
                55, 49, 48, 49, 50, 49, 55, 51, 56, 51, 52, 90, 48, 18,
                49, 16, 48, 14, 6, 3, 85, 4, 3, 19, 7, 116, 101, 115,
                116, 105, 110, 103, 48, 92, 48, 13, 6, 9, 42, -122, 72, -122,
                -9, 13, 1, 1, 1, 5, 0, 3, 75, 0, 48, 72, 2, 65,
                0, -65, 121, -119, -59, 105, 66, -122, -78, -30, -64, 63, -47, 44,
                -48, -104, 103, -47, -108, 42, -38, 46, -8, 32, 49, -29, -26, -112,
                -29, -86, 71, 24, -104, 78, -31, -75, -128, 90, -92, -34, -51, -125,
                -13, 80, 101, -78, 39, -119, -38, 117, 28, 67, -19, -71, -124, -85,
                105, -53, -103, -59, -67, -38, -83, 118, 65, 2, 3, 1, 0, 1,
                48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 4, 5,
                0, 3, 65, 0, -97, -62, 79, -28, 124, -81, 98, 119, -85, -49,
                62, -81, 46, -25, -29, 78, -40, 118, -2, 114, -128, 74, -47, -68,
                52, 11, -14, 30, -46, -95, -26, -108, -19, 110, -63, -70, 61, -75,
                64, 74, -33, -65, -96, 120, -109, 37, 77, -76, 38, -114, 58, -80,
                -122, -39, -65, -31, 37, -30, -126, 126, 17, -82, 92, 64,
            };

        return new X509CertImpl(certData);
    }

    class CMSEngineStub extends CMSEngineDefaultStub {
        public ILogger getLogger() {
            return logger;
        }
    }

    class DBSubsystemStub extends DBSubsystemDefaultStub {
        public IDBSSession createSession() {
            return session;
        }

        public IDBRegistry getRegistry() {
            return registry;
        }
    }
}
