// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.cmscore.test.CMSBaseTestCase;

import junit.framework.Test;
import junit.framework.TestSuite;

public class CertRecordListTest extends CMSBaseTestCase {

    public CertRecordListTest(String name) {
        super(name);
    }

    @Override
    public void cmsTestSetUp() {
    }

    @Override
    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(CertRecordListTest.class);
    }

    public void testProcessCertRecordsUsesSize() throws EBaseException {
        DBVirtualListStub<CertRecord> dbList = new DBVirtualListStub<CertRecord>();
        dbList.size = 5;

        CertRecordList certList = new CertRecordList(dbList);

        assertEquals(5, dbList.size);
        assertEquals(0, dbList.getElementAtCallCount);
        assertEquals(0, dbList.lastIndexGetElementAtCalledWith);

        certList.processCertRecords(0, 4, new ElementProcessorStub());

        assertEquals(8, dbList.size);
        assertEquals(8, dbList.getElementAtCallCount);
        assertEquals(7, dbList.lastIndexGetElementAtCalledWith);
    }

    public static class DBVirtualListStub<T extends IDBObj> extends DBVirtualListDefaultStub<T> {
        public int size = 0;
        public int getElementAtCallCount = 0;
        public int lastIndexGetElementAtCalledWith = 0;

        @Override
        public T getElementAt(int index) {
            getElementAtCallCount++;
            lastIndexGetElementAtCalledWith = index;

            // This simulates the size changing in the middle of
            // processing
            if (index == 3) {
                size = 8;
            }
            return null;
        }

        @Override
        public int getSize() {
            return size;
        }
    }

    public static class ElementProcessorStub implements IElementProcessor {
        @Override
        public void process(Object o) throws EBaseException {
        }
    }
}
