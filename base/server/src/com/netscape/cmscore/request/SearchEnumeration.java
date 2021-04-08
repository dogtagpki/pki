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

import com.netscape.certsrv.dbs.IDBSearchResults;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.RequestId;

public class SearchEnumeration implements IRequestList {

    protected RequestQueue queue;
    protected IDBSearchResults results;

    public SearchEnumeration(RequestQueue queue, IDBSearchResults results) {
        this.queue = queue;
        this.results = results;
    }

    public RequestId nextRequestId() {
        Object object = results.nextElement();

        if (object == null || !(object instanceof RequestRecord)) {
            return null;
        }

        RequestRecord r = (RequestRecord) object;
        return r.mRequestId;
    }

    public boolean hasMoreElements() {
        return results.hasMoreElements();
    }

    public RequestId nextElement() {
        return nextRequestId();
    }

    public SearchEnumeration(IDBSearchResults r) {
        results = r;
    }

    public Object nextRequest() {
        Object object = results.nextElement();

        if (object == null || !(object instanceof RequestRecord)) {
            return null;
        }

        RequestRecord r = (RequestRecord) object;
        return r;
    }

    public IRequest nextRequestObject() {
        RequestRecord record = (RequestRecord) nextRequest();
        if (record != null) {
            return queue.makeRequest(record);
        }
        return null;
    }
}