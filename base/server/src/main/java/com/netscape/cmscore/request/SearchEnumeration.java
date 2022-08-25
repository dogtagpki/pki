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
package com.netscape.cmscore.request;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.dbs.DBSearchResults;

public class SearchEnumeration extends RequestList {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SearchEnumeration.class);

    protected DBSearchResults results;

    public SearchEnumeration(DBSearchResults results) {
        super(null);
        this.results = results;
    }

    @Override
    public RequestId nextRequestId() {
        Object object = results.nextElement();

        if (object == null || !(object instanceof RequestRecord)) {
            return null;
        }

        RequestRecord r = (RequestRecord) object;
        return r.mRequestId;
    }

    @Override
    public boolean hasMoreElements() {
        return results.hasMoreElements();
    }

    @Override
    public RequestId nextElement() {
        return nextRequestId();
    }

    @Override
    public Object nextRequest() {
        Object object = results.nextElement();

        if (object == null || !(object instanceof RequestRecord)) {
            return null;
        }

        RequestRecord r = (RequestRecord) object;
        return r;
    }

    @Override
    public Request nextRequestObject() {
        RequestRecord record = (RequestRecord) nextRequest();
        if (record != null) {
            try {
                return record.toRequest();
            } catch (EBaseException e) {
                logger.error("SearchEnumeration: " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
        return null;
    }
}