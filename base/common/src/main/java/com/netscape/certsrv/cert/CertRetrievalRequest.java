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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 *
 */
package com.netscape.certsrv.cert;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRetrievalRequest implements JSONSerializer {

    protected CertId certId;

    public RequestId requestId;

    public CertRetrievalRequest() {
        // required for JAXB (defaults)
    }

    public CertRetrievalRequest(CertId certId) {
        this.certId = certId;
    }

    /**
     * @return the CertId
     */
    public CertId getCertId() {
        return certId;
    }

    protected void setCertId(CertId certId) {
        this.certId = certId;
    }

    protected void setRequestId(RequestId requestId) {
        this.requestId = requestId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(certId, requestId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertRetrievalRequest other = (CertRetrievalRequest) obj;
        return Objects.equals(certId, other.certId) && Objects.equals(requestId, other.requestId);
    }

}
