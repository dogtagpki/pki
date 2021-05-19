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

import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.dbs.StringMapper;

public class RequestType extends RequestAttr {

    public RequestType() {
        super(Request.ATTR_REQUEST_TYPE, new StringMapper(Schema.LDAP_ATTR_REQUEST_TYPE));
    }

    @Override
    void set(RequestRecord requestRecord, Object o) {
        requestRecord.mRequestType = (String) o;
    }

    @Override
    Object get(RequestRecord requestRecord) {
        return requestRecord.mRequestType;
    }

    @Override
    void read(IRequest request, RequestRecord requestRecord) {
        request.setRequestType(requestRecord.mRequestType);
    }

    @Override
    void add(IRequest request, RequestRecord requestRecord) {
        requestRecord.mRequestType = request.getRequestType();
    }

    @Override
    void mod(ModificationSet mods, IRequest request) {
        addmod(mods, request.getRequestType());
    }
}
