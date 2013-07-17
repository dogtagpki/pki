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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * This represents a user request.
 *
 * @version $Revision$, $Date$
 */
public class CMSRequest implements ICMSRequest {

    private static final String RESULT = "cmsRequestResult";

    // Reason message for request failure
    private String reason = null;

    // http parameters - handier than getting directly from http request.
    private IArgBlock mHttpParams = null;

    // http headers & other info.
    private HttpServletRequest mHttpReq = null;

    // http response.
    private HttpServletResponse mHttpResp = null;

    // http servlet config.
    private ServletConfig mServletConfig = null;

    // http servlet context.
    private ServletContext mServletContext = null;

    // permanent request in request queue.
    private IRequest mRequest = null;

    // whether request processed successfully
    private Integer mStatus = SUCCESS;

    // exception message containing error that occured.
    // note exception could also be thrown seperately.
    private String mError = null;

    // any error description.
    private Vector<String> mErrorDescr = null;

    // any request resulting data;
    Object mResult = null;
    Hashtable<String, Object> mResults = new Hashtable<String, Object>();

    /**
     * Constructor
     */
    public CMSRequest() {
    }

    // set methods use by servlets.

    /**
     * set the HTTP parameters
     */
    public void setHttpParams(IArgBlock httpParams) {
        mHttpParams = httpParams;
    }

    /**
     * set the Request aobject associated with this session
     */
    public void setIRequest(IRequest request) {
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
        if (!status.equals(UNAUTHORIZED) &&
                !status.equals(SUCCESS) &&
                !status.equals(REJECTED) &&
                !status.equals(PENDING) &&
                !status.equals(ERROR) &&
                !status.equals(SVC_PENDING) &&
                !status.equals(EXCEPTION)) {
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
            mErrorDescr = new Vector<String>();
        mErrorDescr.addElement(descr);
    }

    public void setResult(Object result) {
        mResult = result;
        mResults.put(RESULT, result);
    }

    public void setResult(String name, Object result) {
        mResults.put(name, result);
    }

    public IArgBlock getHttpParams() {
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

    public IRequest getIRequest() {
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

    // handy routines for IRequest.

    public void setExtData(String type, String value) {
        if (mRequest != null) {
            mRequest.setExtData(type, value);
        }
    }

    public String getExtData(String type) {
        if (mRequest != null) {
            return mRequest.getExtDataInString(type);
        } else {
            return null;
        }
    }

    // policy errors; set on rejection or possibly deferral.
    public Vector<String> getPolicyMessages() {
        if (mRequest != null) {
            return mRequest.getExtDataInStringVector(IRequest.ERRORS);
        }
        return null;
    }

    /**
     * set default CMS status according to IRequest status.
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
            mStatus = ICMSRequest.SUCCESS;
            return;
        }
        // unexpected resulting request status.
        if (status == RequestStatus.REJECTED) {
            mStatus = ICMSRequest.REJECTED;
            return;
        } // pending or service pending.
        else if (status == RequestStatus.PENDING) {
            mStatus = ICMSRequest.PENDING;
            return;
        } else if (status == RequestStatus.SVC_PENDING) {
            mStatus = ICMSRequest.SVC_PENDING;
            return;
        } else {
            RequestId reqId = mRequest.getRequestId();

            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_UNEXPECTED_REQUEST_STATUS_2",
                            status.toString(), reqId.toString()));
        }
    }

}
