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
package com.netscape.cms.servlet.base;

import java.security.cert.CertificateEncodingException;

import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import com.netscape.certsrv.apps.CMS;
import com.netscape.cms.servlet.cert.model.CertificateData;

/**
 * Base class for CMS RESTful resources
 * 
 * @author alee
 * 
 */
public class CMSResourceService {
    public static final String HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String TRAILER = "-----END NEW CERTIFICATE REQUEST-----";

    // caching parameters
    protected static final int DEFAULT_LONG_CACHE_LIFETIME = 1000;

    protected Response sendConditionalGetResponse(int ctime, Object object, Request request) {
        CacheControl cc = new CacheControl();
        cc.setMaxAge(ctime);
        EntityTag tag = new EntityTag(Integer.toString(object.hashCode()));

        ResponseBuilder builder = request.evaluatePreconditions(tag);
        if (builder != null) {
            builder.cacheControl(cc);
            return builder.build();
        }

        builder = Response.ok(object);
        builder.cacheControl(cc);
        builder.tag(tag);
        return builder.build();
    }

    public CertificateData createCertificateData(org.mozilla.jss.crypto.X509Certificate cert)
            throws CertificateEncodingException {
        CertificateData data = new CertificateData();
        String b64 = HEADER + CMS.BtoA(cert.getEncoded()) + TRAILER;
        data.setB64(b64);
        return data;
    }

}
