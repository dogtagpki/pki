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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Hashtable;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.dbs.CertRecord;

public class LdapRequestListener implements IRequestListener {
    private boolean mInited = false;

    /**
     * handlers for request types (events)
     * each handler implement IRequestListener
     */
    private Hashtable<String, IRequestListener> mRequestListeners = new Hashtable<String, IRequestListener>();

    private IPublisherProcessor mPublisherProcessor = null;

    public LdapRequestListener() {
    }

    public void set(String name, String val) {
    }

    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
        if (mInited)
            return;

        mPublisherProcessor = (IPublisherProcessor) sys;

        mRequestListeners.put(IRequest.ENROLLMENT_REQUEST,
                new LdapEnrollmentListener(mPublisherProcessor));
        mRequestListeners.put(IRequest.RENEWAL_REQUEST,
                new LdapRenewalListener(mPublisherProcessor));
        mRequestListeners.put(IRequest.REVOCATION_REQUEST,
                new LdapRevocationListener(mPublisherProcessor));
        mRequestListeners.put(IRequest.UNREVOCATION_REQUEST,
                new LdapUnrevocationListener(mPublisherProcessor));
        mInited = true;
    }

    public PublishObject getPublishObject(IRequest r) {
        String type = r.getRequestType();
        PublishObject obj = new PublishObject();

        if (type.equals(IRequest.ENROLLMENT_REQUEST)) {
            // in case it's not meant for us
            if (r.getExtDataInInteger(IRequest.RESULT) == null)
                return null;

            // check if request failed.
            if ((r.getExtDataInInteger(IRequest.RESULT)).equals(IRequest.RES_ERROR)) {
                CMS.debug("Request errored. " +
                        "Nothing to publish for enrollment request id " +
                        r.getRequestId());
                return null;
            }
            CMS.debug("Checking publishing for request " +
                    r.getRequestId());
            // check if issued certs is set.
            X509CertImpl[] certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

            if (certs == null || certs.length == 0 || certs[0] == null) {
                CMS.debug(
                        "No certs to publish for request id " +
                                r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else if (type.equals(IRequest.RENEWAL_REQUEST)) {
            // Note we do not remove old certs from directory during renewal
            X509CertImpl[] certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

            if (certs == null || certs.length == 0) {
                CMS.debug("no certs to publish for renewal " +
                        "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else if (type.equals(IRequest.REVOCATION_REQUEST)) {
            X509CertImpl[] revcerts = r.getExtDataInCertArray(IRequest.OLD_CERTS);

            if (revcerts == null || revcerts.length == 0 || revcerts[0] == null) {
                // no certs in revoke.
                CMS.debug(
                        "Nothing to unpublish for revocation " +
                                "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(revcerts);
            return obj;
        } else if (type.equals(IRequest.UNREVOCATION_REQUEST)) {
            X509CertImpl[] certs = r.getExtDataInCertArray(IRequest.OLD_CERTS);

            if (certs == null || certs.length == 0 || certs[0] == null) {
                // no certs in unrevoke.
                CMS.debug(
                        "Nothing to publish for unrevocation " +
                                "request " + r.getRequestId());
                return null;
            }
            obj.setCerts(certs);
            return obj;
        } else {
            CMS.debug("Request errored. " +
                    "Nothing to publish for request id " +
                    r.getRequestId());
            return null;
        }

    }

    public void accept(IRequest r) {
        String type = r.getRequestType();

        IRequestListener handler = mRequestListeners.get(type);

        if (handler == null) {
            CMS.debug(
                    "Nothing to publish for request type " + type);
            return;
        }
        handler.accept(r);
    }

}

class LdapEnrollmentListener implements IRequestListener {
    IPublisherProcessor mProcessor = null;

    public LdapEnrollmentListener(IPublisherProcessor processor) {
        mProcessor = processor;
    }

    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
    }

    public void set(String name, String val) {
    }

    public void accept(IRequest r) {
        CMS.debug(
                "LdapRequestListener handling publishing for enrollment request id " +
                        r.getRequestId());

        String profileId = r.getExtDataInString("profileId");

        if (profileId == null) {
            // in case it's not meant for us
            if (r.getExtDataInInteger(IRequest.RESULT) == null)
                return;

            // check if request failed.
            if ((r.getExtDataInInteger(IRequest.RESULT)).equals(IRequest.RES_ERROR)) {
                CMS.debug("Request errored. " +
                        "Nothing to publish for enrollment request id " +
                        r.getRequestId());
                return;
            }
        }
        CMS.debug("Checking publishing for request " +
                r.getRequestId());
        // check if issued certs is set.
        Certificate[] certs = null;
        if (profileId == null) {
            certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);
        } else {
            certs = new Certificate[1];
            certs[0] = r.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
        }

        if (certs == null || certs.length == 0 || certs[0] == null) {
            CMS.debug(
                    "No certs to publish for request id " + r.getRequestId());
            return;
        }

        if (certs[0] instanceof X509CertImpl)
            acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] certs) {
        Integer results[] = new Integer[certs.length];
        boolean error = false;

        for (int i = 0; i < certs.length; i++) {
            X509CertImpl xcert = (X509CertImpl) certs[i];

            if (xcert == null)
                continue;
            try {
                mProcessor.publishCert(xcert, r);

                results[i] = IRequest.RES_SUCCESS;
                CMS.debug(
                        "acceptX509: Published cert serial no 0x" +
                                xcert.getSerialNumber().toString(16));
                //mProcessor.setPublishedFlag(xcert.getSerialNumber(), true);
            } catch (ELdapException e) {
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH",
                                xcert.getSerialNumber().toString(16), e.toString()));
                results[i] = IRequest.RES_ERROR;
                error = true;
            }
        }
        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus",
                (error == true ? IRequest.RES_ERROR : IRequest.RES_SUCCESS));
    }
}

class LdapRenewalListener implements IRequestListener {
    private IPublisherProcessor mProcessor = null;

    public LdapRenewalListener(IPublisherProcessor processor) {
        mProcessor = processor;
    }

    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
    }

    public void set(String name, String val) {
    }

    public void accept(IRequest r) {
        // Note we do not remove old certs from directory during renewal
        Certificate[] certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

        if (certs == null || certs.length == 0) {
            CMS.debug("no certs to publish for renewal " +
                    "request " + r.getRequestId());
            return;
        }

        acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] certs) {
        X509CertImpl cert = null;

        Integer results[] = new Integer[certs.length];
        boolean error = false;

        for (int i = 0; i < certs.length; i++) {
            cert = (X509CertImpl) certs[i];
            if (cert == null)
                continue; // there was an error issuing this cert.
            try {
                mProcessor.publishCert(cert, r);
                results[i] = IRequest.RES_SUCCESS;
                mProcessor.log(ILogger.LL_INFO,
                        "Published cert serial no 0x" +
                                cert.getSerialNumber().toString(16));
            } catch (ELdapException e) {
                error = true;
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH",
                                cert.getSerialNumber().toString(16), e.toString()));
                results[i] = IRequest.RES_ERROR;
            }
        }
        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus",
                (error == true ? IRequest.RES_ERROR : IRequest.RES_SUCCESS));
    }
}

class LdapRevocationListener implements IRequestListener {
    private IPublisherProcessor mProcessor = null;

    public LdapRevocationListener(IPublisherProcessor processor) {
        mProcessor = processor;
    }

    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
    }

    public void set(String name, String val) {
    }

    public void accept(IRequest r) {
        CMS.debug(
                "Handle publishing for revoke request id " + r.getRequestId());

        // get fields in request.
        Certificate[] certs = r.getExtDataInCertArray(IRequest.OLD_CERTS);

        if (certs == null || certs.length == 0 || certs[0] == null) {
            // no certs in revoke.
            CMS.debug(
                    "Nothing to unpublish for revocation " +
                            "request " + r.getRequestId());
            return;
        }

        acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] revcerts) {
        boolean error = false;
        Integer results[] = new Integer[revcerts.length];

        error = false;
        for (int i = 0; i < revcerts.length; i++) {
            X509CertImpl cert = (X509CertImpl) revcerts[i];

            results[i] = IRequest.RES_ERROR;
            try {
                // We need the enrollment request to sort out predicate
                BigInteger serial = cert.getSerialNumber();
                ICertRecord certRecord = null;
                IAuthority auth = (IAuthority) mProcessor.getAuthority();

                if (auth == null ||
                        !(auth instanceof ICertificateAuthority)) {
                    mProcessor.log(ILogger.LL_WARN,
                            "Trying to get a certificate from non certificate authority.");
                } else {
                    ICertificateRepository certdb =
                            ((ICertificateAuthority) auth).getCertificateRepository();

                    if (certdb == null) {
                        mProcessor.log(ILogger.LL_WARN, "Cert DB is null for " + auth);
                    } else {
                        try {
                            certRecord = certdb.readCertificateRecord(serial);
                        } catch (EBaseException e) {
                            mProcessor.log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSCORE_LDAP_GET_CERT_RECORD",
                                            serial.toString(16), e.toString()));
                        }
                    }
                }

                MetaInfo metaInfo = null;
                String ridString = null;

                if (certRecord != null)
                    metaInfo =
                            (MetaInfo) certRecord.get(ICertRecord.ATTR_META_INFO);
                if (metaInfo == null) {
                    mProcessor.log(ILogger.LL_FAILURE,
                            "failed getting CertRecord.ATTR_META_INFO for cert serial number 0x" +
                                    serial.toString(16));
                } else {
                    ridString = (String) metaInfo.get(ICertRecord.META_REQUEST_ID);
                }

                IRequest req = null;

                if (ridString != null) {
                    RequestId rid = new RequestId(ridString);

                    req = auth.getRequestQueue().findRequest(rid);
                }
                mProcessor.unpublishCert(cert, req);
                results[i] = IRequest.RES_SUCCESS;
                CMS.debug(
                        "Unpublished cert serial no 0x" +
                                cert.getSerialNumber().toString(16));
            } catch (ELdapException e) {
                error = true;
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_UNPUBLISH",
                                cert.getSerialNumber().toString(16), e.toString()));
            } catch (EBaseException e) {
                error = true;
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_FIND",
                                cert.getSerialNumber().toString(16), e.toString()));
            }
        }
        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus",
                (error == true ? IRequest.RES_ERROR : IRequest.RES_SUCCESS));
    }
}

class LdapUnrevocationListener implements IRequestListener {
    private IPublisherProcessor mProcessor = null;

    public LdapUnrevocationListener(IPublisherProcessor processor) {
        mProcessor = processor;
    }

    public void init(ISubsystem sys, IConfigStore config) throws EBaseException {
    }

    public void set(String name, String val) {
    }

    public void accept(IRequest r) {
        CMS.debug(
                "Handle publishing for unrevoke request id " + r.getRequestId());

        // get fields in request.
        Certificate[] certs = r.getExtDataInCertArray(IRequest.OLD_CERTS);

        if (certs == null || certs.length == 0 || certs[0] == null) {
            // no certs in unrevoke.
            CMS.debug(
                    "Nothing to publish for unrevocation " +
                            "request " + r.getRequestId());
            return;
        }

        acceptX509(r, certs);
    }

    public void acceptX509(IRequest r, Certificate[] certs) {
        boolean error = false;
        Integer results[] = new Integer[certs.length];
        X509CertImpl xcert = null;

        for (int i = 0; i < certs.length; i++) {
            results[i] = IRequest.RES_ERROR;
            xcert = (X509CertImpl) certs[i];
            try {
                // We need the enrollment request to sort out predicate
                BigInteger serial = xcert.getSerialNumber();
                ICertRecord certRecord = null;
                IAuthority auth = (IAuthority) mProcessor.getAuthority();

                if (auth == null ||
                        !(auth instanceof ICertificateAuthority)) {
                    mProcessor.log(ILogger.LL_WARN,
                            "Trying to get a certificate from non certificate authority.");
                } else {
                    ICertificateRepository certdb = ((ICertificateAuthority) auth).getCertificateRepository();

                    if (certdb == null) {
                        mProcessor.log(ILogger.LL_WARN, "Cert DB is null for " + auth);
                    } else {
                        try {
                            certRecord = certdb.readCertificateRecord(serial);
                        } catch (EBaseException e) {
                            mProcessor
                                    .log(ILogger.LL_FAILURE,
                                            CMS.getLogMessage("CMSCORE_LDAP_GET_CERT_RECORD", serial.toString(16),
                                                    e.toString()));
                        }
                    }
                }

                MetaInfo metaInfo = null;
                String ridString = null;

                if (certRecord != null)
                    metaInfo =
                            (MetaInfo) certRecord.get(CertRecord.ATTR_META_INFO);
                if (metaInfo == null) {
                    mProcessor.log(ILogger.LL_FAILURE,
                            "Failed getting CertRecord.ATTR_META_INFO for cert serial number 0x" +
                                    serial.toString(16));
                } else {
                    ridString = (String) metaInfo.get(CertRecord.META_REQUEST_ID);
                }

                IRequest req = null;

                if (ridString != null) {
                    RequestId rid = new RequestId(ridString);

                    req = auth.getRequestQueue().findRequest(rid);
                }
                mProcessor.publishCert(xcert, req);
                results[i] = IRequest.RES_SUCCESS;
                CMS.debug(
                        "Published cert serial no 0x" +
                                xcert.getSerialNumber().toString(16));
            } catch (ELdapException e) {
                error = true;
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_PUBLISH",
                                xcert.getSerialNumber().toString(16), e.toString()));
            } catch (EBaseException e) {
                error = true;
                mProcessor.log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_LDAP_CERT_NOT_FIND",
                                xcert.getSerialNumber().toString(16), e.toString()));
            }
        }
        r.setExtData("ldapPublishStatus", results);
        r.setExtData("ldapPublishOverAllStatus",
                (error == true ? IRequest.RES_ERROR : IRequest.RES_SUCCESS));
    }
}
