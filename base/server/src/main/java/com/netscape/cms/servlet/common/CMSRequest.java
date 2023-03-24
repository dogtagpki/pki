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
package com.netscape.cms.servlet.common;

import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.request.Request;

/**
 * This represents a user request.
 *
 * @version $Revision$, $Date$
 */
public class CMSRequest {

    private static final String RESULT = "cmsRequestResult";

    // statuses. the first two are out of band.
    public static final Integer UNAUTHORIZED = Integer.valueOf(1);
    public static final Integer SUCCESS = Integer.valueOf(2);
    public static final Integer PENDING = Integer.valueOf(3);
    public static final Integer SVC_PENDING = Integer.valueOf(4);
    public static final Integer REJECTED = Integer.valueOf(5);
    public static final Integer ERROR = Integer.valueOf(6);
    public static final Integer EXCEPTION = Integer.valueOf(7); // unexpected error.

    // Reason message for request failure
    private String reason = null;

    // http parameters - handier than getting directly from http request.
    private ArgBlock mHttpParams;

    // http headers & other info.
    private HttpServletRequest mHttpReq = null;

    // http response.
    private HttpServletResponse mHttpResp = null;

    // http servlet config.
    private ServletConfig mServletConfig = null;

    // http servlet context.
    private ServletContext mServletContext = null;

    // permanent request in request queue.
    private Request mRequest = null;

    // whether request processed successfully
    private Integer mStatus = CMSRequest.SUCCESS;

    // exception message containing error that occured.
    // note exception could also be thrown seperately.
    private String mError = null;

    // any error description.
    private Vector<String> mErrorDescr = null;

    // any request resulting data;
    Object mResult = null;
    Hashtable<String, Object> mResults = new Hashtable<>();

    /**
     * Constructor
     */
    public CMSRequest() {
    }

    // set methods use by servlets.

    /**
     * set the HTTP parameters
     */
    public void setHttpParams(ArgBlock httpParams) {
        mHttpParams = httpParams;
    }

    /**
     * set the Request aobject associated with this session
     */
    public void setRequest(Request request) {
        mRequest = request;
    }

    /**
     * set the HTTP Request object associated with this session
     */
    public void setHttpReq(HttpServletRequest httpReq) {
        mHttpReq = httpReq;
    }

    /**
     * set the HTTP Response object which is used to create the
     * HTTP response which is sent back to the user
     */
    public void setHttpResp(HttpServletResponse httpResp) {
        mHttpResp = httpResp;
    }

    /**
     * set the servlet configuration. The servlet configuration is
     * read from the WEB-APPS/web.xml file under the &lt;servlet&gt;
     * XML definition. The parameters are delimited by init-param
     * param-name/param-value options as described in the servlet
     * documentation.
     */
    public void setServletConfig(ServletConfig servletConfig) {
        mServletConfig = servletConfig;
    }

    /*
     * set the servlet context. the servletcontext has detail
     * about the currently running request
     */
    public void setServletContext(ServletContext servletContext) {
        mServletContext = servletContext;
    }

    /**
     * Set request status.
     *
     * @param status request status. Allowed values are
     *            UNAUTHORIZED, SUCCESS, REJECTED, PENDING, ERROR, SVC_PENDING
     * @throws IllegalArgumentException if status is not one of the above values
     */
    public void setStatus(Integer status) {
        if (!status.equals(CMSRequest.UNAUTHORIZED) &&
                !status.equals(CMSRequest.SUCCESS) &&
                !status.equals(CMSRequest.REJECTED) &&
                !status.equals(CMSRequest.PENDING) &&
                !status.equals(CMSRequest.ERROR) &&
                !status.equals(CMSRequest.SVC_PENDING) &&
                !status.equals(CMSRequest.EXCEPTION)) {
            throw new IllegalArgumentException(CMS.getLogMessage("CMSGW_BAD_REQ_STATUS"));
        }
        mStatus = status;
    }

    public void setError(EBaseException error) {
        mError = error.toString();
    }

    public void setError(String error) {
        mError = error;
    }

    public void setErrorDescription(String descr) {
        if (mErrorDescr == null)
            mErrorDescr = new Vector<>();
        mErrorDescr.addElement(descr);
    }

    public void setResult(Object result) {
        mResult = result;
        mResults.put(RESULT, result);
    }

    public void setResult(String name, Object result) {
        mResults.put(name, result);
    }

    public ArgBlock getHttpParams() {
        return mHttpParams;
    }

    public HttpServletRequest getHttpReq() {
        return mHttpReq;
    }

    public HttpServletResponse getHttpResp() {
        return mHttpResp;
    }

    public ServletConfig getServletConfig() {
        return mServletConfig;
    }

    public ServletContext getServletContext() {
        return mServletContext;
    }

    public Request getRequest() {
        return mRequest;
    }

    public Integer getStatus() {
        return mStatus;
    }

    public String getError() {
        return mError;
    }

    public Vector<String> getErrorDescr() {
        return mErrorDescr;
    }

    public Object getResult() {
        return mResult;
    }

    public Object getResult(String name) {
        return mResults.get(name);
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }

    // handy routines for Request.

    public void setExtData(String type, String value) {
        if (mRequest != null) {
            mRequest.setExtData(type, value);
        }
    }

    public String getExtData(String type) {
        return mRequest == null ? null : mRequest.getExtDataInString(type);
    }

    // policy errors; set on rejection or possibly deferral.
    public Vector<String> getPolicyMessages() {
        if (mRequest != null) {
            return mRequest.getExtDataInStringVector(Request.ERRORS);
        }
        return null;
    }

    /**
     * set default CMS status according to Request status.
     */
    public void setIRequestStatus() throws EBaseException {
        if (mRequest == null) {
            EBaseException e =
                    new ECMSGWException(CMS.getLogMessage("CMSGW_MISSING_REQUEST"));

            throw e;
        }

        RequestStatus status = mRequest.getRequestStatus();

        // completed equivalent to success by default.
        if (status == RequestStatus.COMPLETE) {
            mStatus = CMSRequest.SUCCESS;
            return;
        }
        // unexpected resulting request status.
        if (status == RequestStatus.REJECTED) {
            mStatus = CMSRequest.REJECTED;
            return;
        } // pending or service pending.
        else if (status == RequestStatus.PENDING) {
            mStatus = CMSRequest.PENDING;
            return;
        } else if (status == RequestStatus.SVC_PENDING) {
            mStatus = CMSRequest.SVC_PENDING;
            return;
        } else {
            RequestId reqId = mRequest.getRequestId();

            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_UNEXPECTED_REQUEST_STATUS_2",
                            status.toString(), reqId.toString()));
        }
    }

}
