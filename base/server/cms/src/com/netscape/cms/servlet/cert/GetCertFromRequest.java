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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.util.Locale;
import java.math.BigInteger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;

/**
 * Gets a issued certificate from a request id.
 *
 * @version $Revision$, $Date$
 */
public class GetCertFromRequest extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 5310646832256611066L;
    private final static String PROP_IMPORT = "importCert";
    protected static final String GET_CERT_FROM_REQUEST_TEMPLATE = "ImportCert.template";
    protected static final String DISPLAY_CERT_FROM_REQUEST_TEMPLATE = "displayCertFromRequest.template";

    protected static final String REQUEST_ID = "requestId";
    protected static final String CERT_TYPE = "certtype";

    protected String mCertFrReqSuccessTemplate = null;
    protected ICMSTemplateFiller mCertFrReqFiller = null;

    protected IRequestQueue mQueue = null;
    protected boolean mImportCert = true;

    public GetCertFromRequest() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template files
     * "displayCertFromRequest.template" and "ImportCert.template"
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplates.remove(ICMSRequest.SUCCESS);
        mQueue = mAuthority.getRequestQueue();
        try {
            String tmp = sc.getInitParameter(
                    PROP_IMPORT);

            if (tmp != null && tmp.trim().equalsIgnoreCase("false"))
                mImportCert = false;

            String defTemplate = null;

            if (mImportCert)
                defTemplate = GET_CERT_FROM_REQUEST_TEMPLATE;
            else
                defTemplate = DISPLAY_CERT_FROM_REQUEST_TEMPLATE;
            if (mAuthority instanceof IRegistrationAuthority)
                defTemplate = "/ra/" + defTemplate;
            else
                defTemplate = "/ca/" + defTemplate;
            mCertFrReqSuccessTemplate = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mCertFrReqSuccessTemplate == null)
                mCertFrReqSuccessTemplate = defTemplate;
            String fillername =
                    sc.getInitParameter(PROP_SUCCESS_TEMPLATE_FILLER);

            if (fillername != null) {
                ICMSTemplateFiller filler = newFillerObject(fillername);

                if (filler != null)
                    mCertFrReqFiller = filler;
            } else {
                mCertFrReqFiller = new CertFrRequestFiller();
            }
        } catch (Exception e) {
            // should never happen.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(),
                            mId));
        }
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param requestId The request ID to search on
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        IArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String requestId = httpParams.getValueAsString(REQUEST_ID, null);

        if (requestId == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_NO_REQUEST_ID_PROVIDED"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_NO_REQUEST_ID_PROVIDED"));
        }
        // check if request Id is valid.
        try {
            new BigInteger(requestId);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_REQ_ID_FORMAT", requestId));
            throw new EBaseException(
                    CMS.getUserMessage(getLocale(httpReq), "CMS_BASE_INVALID_NUMBER_FORMAT_1", requestId));
        }

        IRequest r = mQueue.findRequest(new RequestId(requestId));

        if (r == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_REQUEST_ID_NOT_FOUND", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_ID_NOT_FOUND", requestId));
        }

        if (authToken != null) {
            //if RA, group and requestOwner must match
            String group = authToken.getInString("group");
            if ((group != null) && (group != "") &&
                    group.equals("Registration Manager Agents")) {
                boolean groupMatched = false;
                String reqOwner = r.getRequestOwner();
                if (reqOwner != null) {
                    CMS.debug("GetCertFromRequest process: req owner=" + reqOwner);
                    if (reqOwner.equals(group))
                        groupMatched = true;
                }
                if (groupMatched == false) {
                    CMS.debug("RA group unmatched");
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_REQUEST_ID_NOT_FOUND", requestId));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_REQUEST_ID_NOT_FOUND", requestId));
                }
            }
        }

        if (!((r.getRequestType().equals(IRequest.ENROLLMENT_REQUEST)) ||
                (r.getRequestType().equals(IRequest.RENEWAL_REQUEST)))) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REQUEST_NOT_ENROLLMENT_1", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_NOT_ENROLLMENT", requestId));
        }
        RequestStatus status = r.getRequestStatus();

        if (!status.equals(RequestStatus.COMPLETE)) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REQUEST_NOT_COMPLETED_1", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_NOT_COMPLETED", requestId));
        }
        Integer result = r.getExtDataInInteger(IRequest.RESULT);

        if (result != null && !result.equals(IRequest.RES_SUCCESS)) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REQUEST_HAD_ERROR_1", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_HAD_ERROR", requestId));
        }
        Object o = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

        if (r.getExtDataInString("profile") != null) {
            // handle profile-based request
            X509CertImpl cert = r.getExtDataInCert(IEnrollProfile.REQUEST_ISSUED_CERT);
            X509CertImpl certs[] = new X509CertImpl[1];

            certs[0] = cert;
            o = certs;
        }
        if (o == null || !(o instanceof X509CertImpl[])) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REQUEST_HAD_NO_CERTS_1", requestId));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_REQUEST_HAD_NO_CERTS", requestId));
        }
        if (o instanceof X509CertImpl[]) {
            X509CertImpl[] certs = (X509CertImpl[]) o;

            if (certs == null || certs.length == 0 || certs[0] == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_REQUEST_HAD_NO_CERTS_1", requestId));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_REQUEST_HAD_NO_CERTS", requestId));
            }

            // for importsCert to get the crmf_reqid.
            cmsReq.setIRequest(r);

            cmsReq.setStatus(ICMSRequest.SUCCESS);

            if (mImportCert &&
                    checkImportCertToNav(cmsReq.getHttpResp(), httpParams, certs[0])) {
                return;
            }
            try {
                cmsReq.setResult(certs);
                renderTemplate(cmsReq, mCertFrReqSuccessTemplate, mCertFrReqFiller);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGE_ERROR_DISPLAY_TEMPLATE_1",
                                mCertFrReqSuccessTemplate, e.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
            }
        }
        return;
    }
}

class CertFrRequestFiller extends ImportCertsTemplateFiller {
    public CertFrRequestFiller() {
    }

    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e)
            throws Exception {
        CMSTemplateParams tparams =
                super.getTemplateParams(cmsReq, authority, locale, e);
        String reqId = cmsReq.getHttpParams().getValueAsString(
                GetCertFromRequest.REQUEST_ID);

        tparams.getHeader().addStringValue(GetCertFromRequest.REQUEST_ID, reqId);

        if (reqId != null) {
            IRequest r = authority.getRequestQueue().findRequest(new RequestId(reqId));
            if (r != null) {
                boolean noCertImport = true;
                String certType = r.getExtDataInString(IRequest.HTTP_PARAMS, IRequest.CERT_TYPE);

                if (certType != null && certType.equals(IRequest.CLIENT_CERT)) {
                    noCertImport = false;
                }
                tparams.getHeader().addBooleanValue("noCertImport", noCertImport);

                X509CertImpl[] certs = r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

                if (certs != null) {
                    X509CertInfo info = (X509CertInfo) certs[0].get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
                    CertificateExtensions extensions = (CertificateExtensions) info.get(X509CertInfo.EXTENSIONS);

                    tparams.getHeader().addStringValue(GetCertFromRequest.CERT_TYPE, "x509");

                    boolean emailCert = false;

                    if (extensions != null) {
                        for (int i = 0; i < extensions.size(); i++) {
                            Extension ext = extensions.elementAt(i);

                            if (ext instanceof NSCertTypeExtension) {
                                NSCertTypeExtension type = (NSCertTypeExtension) ext;

                                if (((Boolean) type.get(NSCertTypeExtension.EMAIL)).booleanValue())
                                    emailCert = true;
                            }
                            if (ext instanceof KeyUsageExtension) {
                                KeyUsageExtension usage =
                                        (KeyUsageExtension) ext;

                                try {
                                    if (((Boolean) usage.get(KeyUsageExtension.DIGITAL_SIGNATURE)).booleanValue() ||
                                            ((Boolean) usage.get(KeyUsageExtension.DATA_ENCIPHERMENT)).booleanValue())
                                        emailCert = true;
                                } catch (ArrayIndexOutOfBoundsException e0) {
                                    // bug356108:
                                    // In case there is only DIGITAL_SIGNATURE,
                                    // don't report error
                                }
                            }
                        }
                    }
                    tparams.getHeader().addBooleanValue("emailCert", emailCert);
                }
            }
        }

        return tparams;
    }
}
