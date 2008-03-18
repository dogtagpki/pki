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
package com.netscape.cms.servlet.processors;


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;

import java.util.StringTokenizer;
import java.util.Vector;
import java.util.Enumeration;
import java.util.Date;
import java.util.Hashtable;

import java.io.*;

import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.security.PublicKey;


import netscape.security.util.*;
import netscape.security.x509.*;
import netscape.security.pkcs.*;
import netscape.security.util.ObjectIdentifier;
import netscape.security.util.DerValue;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.ChallengeResponseException;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.pkix.cms.*;
import org.mozilla.jss.pkix.cmc.*;
import org.mozilla.jss.pkcs10.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.pkcs11.*;

import com.netscape.cms.servlet.*;

import com.netscape.certsrv.apps.*;

import com.netscape.certsrv.authority.*;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.RequestId;

import com.netscape.certsrv.authentication.*;
import com.netscape.cms.servlet.*;

import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.AuditFormat;

import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.base.*;
import java.math.*;

import com.netscape.cms.servlet.processors.IPKIProcessor;
import com.netscape.cms.servlet.processors.PKIProcessor;


/**
 * KeyGenProcess parses Certificate request matching the
 * KEYGEN tag format used by Netscape Communicator 4.x
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class KeyGenProcessor extends PKIProcessor {

    public KeyGenProcessor() {
        super();
    }

    public KeyGenProcessor(CMSRequest cmsReq, CMSServlet servlet) {
        super(cmsReq, servlet);

    }

    public void process(CMSRequest cmsReq)
        throws EBaseException {
    }

    public void fillCertInfo(
        String protocolString, X509CertInfo certInfo,
        IAuthToken authToken, IArgBlock httpParams)
        throws EBaseException {

        CMS.debug("KeyGenProcessor: fillCertInfo");

        if (mServlet == null) {
            return;
        }

        KeyGenInfo keyGenInfo = httpParams.getValueAsKeyGenInfo(
                PKIProcessor.SUBJECT_KEYGEN_INFO, null);
    
        // fill key
        X509Key key = null;

        key = keyGenInfo.getSPKI();
        if (key == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_MISSING_KEY_IN_KEYGENINFO"));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_MISSING_KEY_IN_KEYGENINFO"));
        }
        try {
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                "Could not set key into certInfo from keygen. Error " + e);
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_SET_KEY_FROM_KEYGEN_FAILED", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_KEYGEN_1", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_SET_KEY_FROM_KEYGEN_FAILED", e.toString()));
        }

        String authMgr = mServlet.getAuthMgr();

        // if not authenticated, fill subject name, validity & extensions
        // from authtoken.
        if (authToken == null) {
            fillCertInfoFromForm(certInfo, httpParams);
        } else {
            if (authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) == null) {
                // allow special case for agent gateway in admin enroll
                // and bulk issuance.
                if (!authMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID) && 
                    !authMgr.equals(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID)) {
                    log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                    throw new ECMSGWException(
                      CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                }
                fillCertInfoFromForm(certInfo, httpParams);
            } else {
                fillCertInfoFromAuthToken(certInfo, authToken);
            }
        }
    }
}
