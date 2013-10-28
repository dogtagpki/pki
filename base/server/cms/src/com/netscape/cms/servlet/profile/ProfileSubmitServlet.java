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
package com.netscape.cms.servlet.profile;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.servlet.cert.EnrollmentProcessor;
import com.netscape.cms.servlet.cert.RenewalProcessor;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.processors.CAProcessor;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet submits end-user request into the profile framework.
 *
 * @author Christina Fu (renewal support)
 * @version $Revision$, $Date$
 */
public class ProfileSubmitServlet extends ProfileServlet {

    /**
     *
     */
    private static final long serialVersionUID = 7557922703180866442L;
    private final static String SUCCESS = "0";
    private final static String FAILED = "1";

    public ProfileSubmitServlet() {
    }

    /**
     * initialize the servlet. And instance of this servlet can
     * be set up to always issue certificates against a certain profile
     * by setting the 'profileId' configuration in the servletConfig
     * If not, the user must specify the profileID when submitting the request
     *
     * "ImportCert.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    /**
     * Process the HTTP request
     * <P>
     *
     * (Certificate Request Processed - either an automated "EE" profile based cert acceptance, or an automated "EE"
     * profile based cert rejection)
     * <P>
     *
     * <ul>
     * <li>http.param profileId ID of profile to use to process request
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     * @exception EBaseException an error has occurred
     */

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();
        boolean xmlOutput = getXMLOutput(request);

        Locale locale = getLocale(request);

        HashMap<String, Object> results = null;
        String renewal = request.getParameter("renewal");

        try {
            if ((renewal != null) && (renewal.equalsIgnoreCase("true"))) {
                CMS.debug("ProfileSubmitServlet: isRenewal true");
                RenewalProcessor processor = new RenewalProcessor("caProfileSubmit", locale);
                results = processor.processRenewal(cmsReq);
            } else {
                CMS.debug("ProfileSubmitServlet: isRenewal false");
                EnrollmentProcessor processor = new EnrollmentProcessor("caProfileSubmit", locale);
                results = processor.processEnrollment(cmsReq);
            }
        } catch (BadRequestDataException e) {
            CMS.debug("ProfileSubmitServlet: bad data provided in processing request: " + e.toString());
            errorExit(response, xmlOutput, e.getMessage(), null);
            return;
        } catch (EAuthzException e) {
            CMS.debug("ProfileSubmitServlet: authorization error in processing request: " + e.toString());
            errorExit(response, xmlOutput, e.getMessage(), null);
            return;
        } catch (EAuthException e) {
            CMS.debug("ProfileSubmitServlet: authentication error in processing request: " + e.toString());
            errorExit(response, xmlOutput, e.getMessage(), null);
            return;
        } catch (EBaseException e) {
            e.printStackTrace();
            CMS.debug("ProfileSubmitServlet: error in processing request: " + e.toString());
            errorExit(response, xmlOutput, e.getMessage(), null);
            return;
        }

        IRequest[] reqs = (IRequest []) results.get(CAProcessor.ARG_REQUESTS);
        String errorCode = (String) results.get(CAProcessor.ARG_ERROR_CODE);
        String errorReason = (String) results.get(CAProcessor.ARG_ERROR_REASON);
        IProfile profile = (IProfile) results.get(CAProcessor.ARG_PROFILE);
        ArgSet args = new ArgSet();

        if (errorCode != null) {
            if (xmlOutput) {
                String requestIds = "";
                for (IRequest req : reqs) {
                    requestIds += "  " + req.getRequestId().toString();
                }

                outputError(response, errorCode, errorReason, requestIds);
            } else {
                ArgList requestlist = new ArgList();

                for (IRequest req : reqs) {
                    ArgSet requestset = new ArgSet();
                    requestset.set(ARG_REQUEST_ID, req.getRequestId().toString());
                    requestlist.add(requestset);
                }
                args.set(ARG_REQUEST_LIST, requestlist);
                args.set(ARG_ERROR_CODE, errorCode);
                args.set(ARG_ERROR_REASON, errorReason);
                outputTemplate(request, response, args);
            }
            return;
        }

        if (xmlOutput) {
            xmlOutput(response, profile, locale, reqs);
        } else {
            ArgList outputlist = new ArgList();
            for (int k = 0; k < reqs.length; k++) {

                setOutputIntoArgs(profile, outputlist, locale, reqs[k]);
                args.set(ARG_OUTPUT_LIST, outputlist);
            }

            CMS.debug("ProfileSubmitServlet: done serving");

            ArgList requestlist = new ArgList();

            for (int k = 0; k < reqs.length; k++) {
                ArgSet requestset = new ArgSet();

                requestset.set(ARG_REQUEST_ID,
                        reqs[k].getRequestId().toString());
                requestlist.add(requestset);
            }
            args.set(ARG_REQUEST_LIST, requestlist);
            args.set(ARG_ERROR_CODE, "0");
            args.set(ARG_ERROR_REASON, "");

            outputTemplate(request, response, args);
        }
    }

    private void setOutputIntoArgs(IProfile profile, ArgList outputlist, Locale locale, IRequest req) {
        Enumeration<String> outputIds = profile.getProfileOutputIds();

        if (outputIds != null) {
            while (outputIds.hasMoreElements()) {
                String outputId = outputIds.nextElement();
                IProfileOutput profileOutput = profile.getProfileOutput(outputId);

                Enumeration<String> outputNames = profileOutput.getValueNames();

                if (outputNames != null) {
                    while (outputNames.hasMoreElements()) {
                        ArgSet outputset = new ArgSet();
                        String outputName = outputNames.nextElement();
                        IDescriptor outputDesc =
                                profileOutput.getValueDescriptor(locale, outputName);

                        if (outputDesc == null)
                            continue;
                        String outputSyntax = outputDesc.getSyntax();
                        String outputConstraint = outputDesc.getConstraint();
                        String outputValueName = outputDesc.getDescription(locale);
                        String outputValue = null;

                        try {
                            outputValue = profileOutput.getValue(outputName,
                                    locale, req);
                        } catch (EProfileException e) {
                            CMS.debug("ProfileSubmitServlet: " + e.toString());
                        }

                        outputset.set(ARG_OUTPUT_ID, outputName);
                        outputset.set(ARG_OUTPUT_SYNTAX, outputSyntax);
                        outputset.set(ARG_OUTPUT_CONSTRAINT, outputConstraint);
                        outputset.set(ARG_OUTPUT_NAME, outputValueName);
                        outputset.set(ARG_OUTPUT_VAL, outputValue);
                        outputlist.add(outputset);
                    }
                }
            }
        }
    }

    private void errorExit(HttpServletResponse response, boolean xmlOutput, String message, String requestId)
            throws EBaseException {
        if (xmlOutput) {
            outputError(response, FAILED, message, requestId);
        } else {
            ArgSet args = new ArgSet();
            args.set(ARG_ERROR_CODE, "1");
            args.set(ARG_ERROR_REASON, message);
            outputTemplate(xmlOutput, response, args);
        }

        for (String event : statEvents) {
            endTiming(event);
        }
    }

    private boolean getXMLOutput(HttpServletRequest request) {
        boolean xmlOutput = false;

        String v = request.getParameter("xml");
        if ((v != null) && (v.equalsIgnoreCase("true"))) {
            xmlOutput = true;
        }
        v = request.getParameter("xmlOutput");
        if ((v != null) && (v.equalsIgnoreCase("true"))) {
            xmlOutput = true;
        }
        if (xmlOutput) {
            CMS.debug("xmlOutput true");
        } else {
            CMS.debug("xmlOutput false");
        }
        return xmlOutput;
    }

    private void xmlOutput(HttpServletResponse httpResp, IProfile profile, Locale locale, IRequest[] reqs) {
        try {
            XMLObject xmlObj = null;
            xmlObj = new XMLObject();

            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            Node n = xmlObj.createContainer(root, "Requests");
            CMS.debug("ProfileSubmitServlet xmlOutput: req len = " + reqs.length);

            for (int i = 0; i < reqs.length; i++) {
                Node subnode = xmlObj.createContainer(n, "Request");
                xmlObj.addItemToContainer(subnode, "Id", reqs[i].getRequestId().toString());
                X509CertInfo certInfo =
                        reqs[i].getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);
                if (certInfo != null) {
                    String subject = "";
                    subject = certInfo.get(X509CertInfo.SUBJECT).toString();
                    xmlObj.addItemToContainer(subnode, "SubjectDN", subject);
                } else {
                    CMS.debug("ProfileSubmitServlet xmlOutput: no certInfo found in request");
                }
                Enumeration<String> outputIds = profile.getProfileOutputIds();
                if (outputIds != null) {
                    while (outputIds.hasMoreElements()) {
                        String outputId = outputIds.nextElement();
                        IProfileOutput profileOutput = profile.getProfileOutput(outputId);
                        Enumeration<String> outputNames = profileOutput.getValueNames();
                        if (outputNames != null) {
                            while (outputNames.hasMoreElements()) {
                                String outputName = outputNames.nextElement();
                                if (!outputName.equals("b64_cert") && !outputName.equals("pkcs7"))
                                    continue;
                                try {
                                    String outputValue = profileOutput.getValue(outputName, locale, reqs[i]);
                                    if (outputName.equals("b64_cert")) {
                                        String ss = Cert.normalizeCertStrAndReq(outputValue);
                                        outputValue = Cert.stripBrackets(ss);
                                        byte[] bcode = CMS.AtoB(outputValue);
                                        X509CertImpl impl = new X509CertImpl(bcode);
                                        xmlObj.addItemToContainer(subnode,
                                                "serialno", impl.getSerialNumber().toString(16));
                                        xmlObj.addItemToContainer(subnode, "b64", outputValue);
                                    }// if b64_cert
                                    else if (outputName.equals("pkcs7")) {
                                        String ss = Cert.normalizeCertStrAndReq(outputValue);
                                        xmlObj.addItemToContainer(subnode, "pkcs7", ss);
                                    }

                                } catch (EProfileException e) {
                                    CMS.debug("ProfileSubmitServlet xmlOutput: " + e.toString());
                                } catch (Exception e) {
                                    CMS.debug("ProfileSubmitServlet xmlOutput: " + e.toString());
                                }
                            }
                        }
                    }
                }
            }

            byte[] cb = xmlObj.toByteArray();
            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("Failed to send the XML output");
        }
    }

}
