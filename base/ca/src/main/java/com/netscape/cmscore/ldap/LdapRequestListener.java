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
package com.netscape.cmscore.ldap;

import java.util.Hashtable;

import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

public class LdapRequestListener extends RequestListener {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapRequestListener.class);

    /**
     * handlers for request types (events)
     * each handler implement IRequestListener
     */
    private Hashtable<String, RequestListener> mRequestListeners = new Hashtable<>();

    public LdapRequestListener() {
    }

    @Override
    public void set(String name, String val) {
    }

    public void setPublisherProcessor(CAPublisherProcessor publisherProcessor) {

        mRequestListeners.put(Request.ENROLLMENT_REQUEST,
                new LdapEnrollmentListener(publisherProcessor));

        mRequestListeners.put(Request.RENEWAL_REQUEST,
                new LdapRenewalListener(publisherProcessor));

        mRequestListeners.put(Request.REVOCATION_REQUEST,
                new LdapRevocationListener(publisherProcessor));

        mRequestListeners.put(Request.UNREVOCATION_REQUEST,
                new LdapUnrevocationListener(publisherProcessor));
    }

    @Override
    public void init(Subsystem sys, ConfigStore config) throws EBaseException {
    }

    public PublishObject getPublishObject(Request r) {
        String type = r.getRequestType();
        PublishObject obj = new PublishObject();

        if (type.equals(Request.ENROLLMENT_REQUEST)) {
            // in case it's not meant for us
            if (r.getExtDataInInteger(Request.RESULT) == null)
                return null;

            // check if request failed.
            if ((r.getExtDataInInteger(Request.RESULT)).equals(Request.RES_ERROR)) {
                logger.warn("Request errored. " +
                        "Nothing to publish for enrollment request id " +
                        r.getRequestId());
                return null;
            }
            logger.debug("Checking publishing for request " + r.getRequestId());
            // check if issued certs is set.
            X509CertImpl[] certs = r.getExtDataInCertArray(Request.ISSUED_CERTS);

            if (certs == null || certs.length == 0 || certs[0] == null) {
                logger.warn("No certs to publish for request id " + r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else if (type.equals(Request.RENEWAL_REQUEST)) {
            // Note we do not remove old certs from directory during renewal
            X509CertImpl[] certs = r.getExtDataInCertArray(Request.ISSUED_CERTS);

            if (certs == null || certs.length == 0) {
                logger.warn("no certs to publish for renewal " +
                        "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else if (type.equals(Request.REVOCATION_REQUEST)) {
            X509CertImpl[] revcerts = r.getExtDataInCertArray(Request.OLD_CERTS);

            if (revcerts == null || revcerts.length == 0 || revcerts[0] == null) {
                // no certs in revoke.
                logger.warn("Nothing to unpublish for revocation " +
                                "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(revcerts);
            return obj;
        } else if (type.equals(Request.UNREVOCATION_REQUEST)) {
            X509CertImpl[] certs = r.getExtDataInCertArray(Request.OLD_CERTS);

            if (certs == null || certs.length == 0 || certs[0] == null) {
                // no certs in unrevoke.
                logger.warn("Nothing to publish for unrevocation " +
                                "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else {
            logger.warn("Request errored. " +
                    "Nothing to publish for request id " +
                    r.getRequestId());
            return null;
        }

    }

    @Override
    public void accept(Request r) {
        String type = r.getRequestType();

        RequestListener handler = mRequestListeners.get(type);

        if (handler == null) {
            logger.warn("Nothing to publish for request type " + type);
            return;
        }
        handler.accept(r);
    }

}
