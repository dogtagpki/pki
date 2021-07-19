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

package com.netscape.certsrv.cert;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.CMSRequestInfo;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRequestInfo extends CMSRequestInfo {

    public static final String REQ_COMPLETE = "complete";
    public static final String RES_SUCCESS = "success";
    public static final String RES_ERROR = "error";

    protected CertId certId;

    protected String certURL;

    protected String certRequestType;

    protected String operationResult;

    protected String errorMessage;

    public CertRequestInfo() {
        // required to be here for JAXB (defaults)
    }

    /**
     * @param certRequestType to set
     */

    public void setCertRequestType(String certRequestType) {
        this.certRequestType = certRequestType;
    }

    /**
     * @return the certRequestType
     */

    public String getCertRequestType() {
        return certRequestType;
    }

    /**
     * set the certURL
     */
    public void setCertURL(String certURL) {
        this.certURL = certURL;
    }

    /**
     * @return the certURL
     */
    public String getCertURL() {
        return certURL;
    }

    /**
     * @return the certId
     */
    public CertId getCertId() {
        return certId;
    }

    public void setCertId(CertId certId) {
        this.certId = certId;
    }

    public String getOperationResult() {
        return operationResult;
    }

    public void setOperationResult(String operationResult) {
        this.operationResult = operationResult;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((certId == null) ? 0 : certId.hashCode());
        result = prime * result + ((certRequestType == null) ? 0 : certRequestType.hashCode());
        result = prime * result + ((certURL == null) ? 0 : certURL.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertRequestInfo other = (CertRequestInfo) obj;
        if (certId == null) {
            if (other.certId != null)
                return false;
        } else if (!certId.equals(other.certId))
            return false;
        if (certRequestType == null) {
            if (other.certRequestType != null)
                return false;
        } else if (!certRequestType.equals(other.certRequestType))
            return false;
        if (certURL == null) {
            if (other.certURL != null)
                return false;
        } else if (!certURL.equals(other.certURL))
            return false;
        return true;
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
