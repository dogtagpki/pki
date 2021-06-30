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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.cert;

import java.util.Date;

import javax.ws.rs.FormParam;

import org.mozilla.jss.netscape.security.x509.RevocationReason;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRevokeRequest implements JSONSerializer {

    RevocationReason reason;
    Date invalidityDate;
    String comments;
    String encoded;
    Long nonce;


    @FormParam("revocationReason")
    public RevocationReason getReason() {
        return reason;
    }

    public void setReason(RevocationReason reason) {
        this.reason = reason;
    }

    @FormParam("invalidityDate")
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public void setInvalidityDate(Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    @FormParam(IRequest.REQUESTOR_COMMENTS)
    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    @FormParam("b64eCertificate")
    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
    }

    @FormParam("nonce")
    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((comments == null) ? 0 : comments.hashCode());
        result = prime * result + ((encoded == null) ? 0 : encoded.hashCode());
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
        result = prime * result + ((reason == null) ? 0 : reason.hashCode());
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
        CertRevokeRequest other = (CertRevokeRequest) obj;
        if (comments == null) {
            if (other.comments != null)
                return false;
        } else if (!comments.equals(other.comments))
            return false;
        if (encoded == null) {
            if (other.encoded != null)
                return false;
        } else if (!encoded.equals(other.encoded))
            return false;
        if (invalidityDate == null) {
            if (other.invalidityDate != null)
                return false;
        } else if (!invalidityDate.equals(other.invalidityDate))
            return false;
        if (nonce == null) {
            if (other.nonce != null)
                return false;
        } else if (!nonce.equals(other.nonce))
            return false;
        if (reason == null) {
            if (other.reason != null)
                return false;
        } else if (!reason.equals(other.reason))
            return false;
        return true;
    }

}
