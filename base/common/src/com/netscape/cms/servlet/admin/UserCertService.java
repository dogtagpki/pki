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

package com.netscape.cms.servlet.admin;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import netscape.ldap.LDAPException;
import netscape.security.pkcs.PKCS7;
import netscape.security.x509.X509CertImpl;

import org.jboss.resteasy.plugins.providers.atom.Link;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCertResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIException;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

/**
 * @author Endi S. Dewata
 */
public class UserCertService extends PKIService implements UserCertResource {

    public final static int DEFAULT_SIZE = 20;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    public UserCertData createUserCertData(String userID, X509Certificate cert) throws Exception {

        UserCertData userCertData = new UserCertData();

        userCertData.setVersion(cert.getVersion());
        userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
        userCertData.setIssuerDN(cert.getIssuerDN().toString());
        userCertData.setSubjectDN(cert.getSubjectDN().toString());

        userID = URLEncoder.encode(userID, "UTF-8");
        String certID = URLEncoder.encode(userCertData.getID(), "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(UserCertResource.class).path("{certID}").build(userID, certID);
        userCertData.setLink(new Link("self", uri));

        return userCertData;
    }

    /**
     * List user certificate(s)
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) {
        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new PKIException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IUser user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            UserCertCollection response = new UserCertCollection();

            X509Certificate[] certs = user.getX509Certificates();
            if (certs != null) {
                for (int i=start; i<start+size && i<certs.length; i++) {
                    X509Certificate cert = certs[i];
                    response.addCert(createUserCertData(userID, cert));
                }

                if (start > 0) {
                    URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                    response.addLink(new Link("prev", uri));
                }

                if (start+size < certs.length) {
                    URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                    response.addLink(new Link("next", uri));
                }
            }

            return response;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public UserCertData getUserCert(String userID, String certID) {
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                throw new PKIException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IUser user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            X509Certificate[] certs = user.getX509Certificates();

            if (certs == null) {
                throw new PKIException("Certificate not found");
            }

            try {
                certID = URLDecoder.decode(certID, "UTF-8");
            } catch (Exception e) {
                throw new PKIException(e.getMessage());
            }

            for (X509Certificate cert : certs) {

                UserCertData userCertData = createUserCertData(userID, cert);

                if (!userCertData.getID().equals(certID)) continue;

                ICertPrettyPrint print = CMS.getCertPrettyPrint(cert);
                userCertData.setPrettyPrint(print.toString(getLocale()));

                // add base64 encoding
                String base64 = CMS.getEncodedCert(cert);
                userCertData.setEncoded(base64);

                return userCertData;
            }

            throw new PKIException("Certificate not found");

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Adds a certificate to a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response addUserCert(String userID, UserCertData userCertData) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new PKIException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IUser user = userGroupManager.createUser(userID);

            String encoded = userCertData.getEncoded();
            encoded = Cert.normalizeCertStrAndReq(encoded);
            encoded = Cert.stripBrackets(encoded);

            // no cert is a success
            if (encoded == null) {
                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);
                return Response.ok().build();
            }

            // only one cert added per operation
            X509Certificate cert = null;

            // Base64 decode cert
            byte binaryCert[] = Utils.base64decode(encoded);

            try {
                cert = new X509CertImpl(binaryCert);

            } catch (CertificateException e) {
                // ignore
            }

            if (cert == null) {
                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(binaryCert);

                    X509Certificate p7certs[] = pkcs7.getCertificates();

                    if (p7certs.length == 0) {
                        throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR"));
                    }

                    // fix for 370099 - cert ordering can not be assumed
                    // find out the ordering ...

                    // self-signed and alone? take it. otherwise test
                    // the ordering
                    if (p7certs[0].getSubjectDN().toString().equals(
                            p7certs[0].getIssuerDN().toString()) &&
                            (p7certs.length == 1)) {
                        cert = p7certs[0];
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));

                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        cert = p7certs[0];
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));

                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        cert = p7certs[p7certs.length - 1];

                    } else {
                        // not a chain, or in random order
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));
                        throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR"));
                    }

                    CMS.debug("UserCertResourceService: "
                            + CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending == true) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }

                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        CMS.debug("UserCertResourceService: "
                                + CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof InternalCertificate) {
                            ((InternalCertificate) leafCert).setSSLTrust(
                                    InternalCertificate.VALID_CA |
                                            InternalCertificate.TRUSTED_CA |
                                            InternalCertificate.TRUSTED_CLIENT_CA);
                        } else {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }

                /*
                } catch (CryptoManager.UserCertConflictException e) {
                    // got a "user cert" in the chain, most likely the CA
                    // cert of this instance, which has a private key.  Ignore
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_PKS7_IGNORED", e.toString()));
                */
                } catch (Exception e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR"));
                }
            }

            try {
                CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                cert.checkValidity(); // throw exception if fails

                user.setX509Certificates(new X509Certificate[] { cert });
                userGroupManager.addUserCert(user);

                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);

                // read the data back

                userCertData.setVersion(cert.getVersion());
                userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
                userCertData.setIssuerDN(cert.getIssuerDN().toString());
                userCertData.setSubjectDN(cert.getSubjectDN().toString());
                String certID = userCertData.getID();

                userCertData = getUserCert(userID, URLEncoder.encode(certID, "UTF-8"));

                return Response
                        .created(userCertData.getLink().getHref())
                        .entity(userCertData)
                        .type(MediaType.APPLICATION_XML)
                        .build();

            } catch (CertificateExpiredException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(cert.getSubjectDN())));
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_EXPIRED"));

            } catch (CertificateNotYetValidException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(cert.getSubjectDN())));
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_NOT_YET_VALID"));

            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                    throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_CERT_EXISTS"));
                } else {
                    throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED"));
                }
            }

        } catch (PKIException e) {
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED"));
        }
    }

    /**
     * Removes a certificate for a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * In this method, "certDN" is actually a combination of version, serialNumber, issuerDN, and SubjectDN.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public void removeUserCert(String userID, String certID) {

        try {
            certID = URLDecoder.decode(certID, "UTF-8");
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setID(certID);
        removeUserCert(userID, userCertData);
    }

    public void removeUserCert(String userID, UserCertData userCertData) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new PKIException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IUser user = userGroupManager.createUser(userID);
            String certID = userCertData.getID();

            // no certDN is a success
            if (certID == null) {
                auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);
                return;
            }

            user.setCertDN(certID);

            userGroupManager.removeUserCert(user);

            auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);

        } catch (PKIException e) {
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED"));
        }
    }

    public void log(int level, String message) {
        log(ILogger.S_USRGRP, level, message);
    }

    public void auditAddUserCert(String id, UserCertData userCertData, String status) {
        audit(OpDef.OP_ADD, id, getParams(userCertData), status);
    }

    public void auditDeleteUserCert(String id, UserCertData userCertData, String status) {
        audit(OpDef.OP_DELETE, id, getParams(userCertData), status);
    }

    public void audit(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_USER_CERTS, type, id, params, status);
    }
}
