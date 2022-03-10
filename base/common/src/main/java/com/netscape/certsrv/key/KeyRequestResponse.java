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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.key;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KeyRequestResponse implements JSONSerializer {

    KeyRequestInfo requestInfo;
    KeyData keyData;

    public KeyRequestInfo getRequestInfo() {
        return requestInfo;
    }

    public void setRequestInfo(KeyRequestInfo requestInfo) {
        this.requestInfo = requestInfo;
    }

    public KeyData getKeyData() {
        return keyData;
    }

    public void setKeyData(KeyData keyData) {
        this.keyData = keyData;
    }

    public KeyId getKeyId(){
        return this.requestInfo.getKeyId();
    }

    public RequestId getRequestId(){
        return this.requestInfo.getRequestID();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((keyData == null) ? 0 : keyData.hashCode());
        result = prime * result + ((requestInfo == null) ? 0 : requestInfo.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KeyRequestResponse other = (KeyRequestResponse) obj;
        if (keyData == null) {
            if (other.keyData != null)
                return false;
        } else if (!keyData.equals(other.keyData))
            return false;
        if (requestInfo == null) {
            if (other.requestInfo != null)
                return false;
        } else if (!requestInfo.equals(other.requestInfo))
            return false;
        return true;
    }

}
