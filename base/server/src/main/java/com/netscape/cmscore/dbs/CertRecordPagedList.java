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
// (C) 2023 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

import java.util.Iterator;
import java.util.List;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBPagedSearch;

/**
* Contain all records in a page for a paged search.
*
* @author Marco Fargetta {@literal <mfargett@redhat.com>}
*/
public class CertRecordPagedList implements Iterable<CertRecord> {
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecordPagedList.class);

    private DBPagedSearch<CertRecord> pages;
    private Iterator<CertRecord> pageEntries;
    /**
     * Constructs a request paged.
     */
    public CertRecordPagedList(DBPagedSearch<CertRecord> pages) {
        this.pages = pages;
        try {
            pageEntries = pages.getPage().iterator();
        } catch (EBaseException e) {
            throw new RuntimeException("CertRecordPagedList: Error to get a new page", e);
        }
    }

    @Override
    public Iterator<CertRecord> iterator() {
        return new CertRecordPageIterator();
    }

    class CertRecordPageIterator implements Iterator<CertRecord> {

        @Override
        public boolean hasNext() {
            if (!pageEntries.hasNext()) {
                try {
                    List<CertRecord> newPage = pages.getPage();
                    pageEntries = newPage.iterator();
                } catch (EBaseException e) {
                    throw new RuntimeException("CertRecordPagedList: Error to get a new page", e);
                }
            }
            return pageEntries.hasNext();
        }

        @Override
        public CertRecord next() {
            if (hasNext()) {
                return pageEntries.next();
            }
            return null;
        }

    }
}
