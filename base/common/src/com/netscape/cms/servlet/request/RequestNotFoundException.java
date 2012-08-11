package com.netscape.cms.servlet.request;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.servlet.base.PKIException;

public class RequestNotFoundException extends PKIException {

    private static final long serialVersionUID = -4784839378360933483L;

    public RequestId requestId;

    public RequestNotFoundException(RequestId requestId) {
        this(requestId, "Request ID "+requestId.toHexString()+" not found");
    }

    public RequestNotFoundException(RequestId requestId, String message) {
        super(Response.Status.NOT_FOUND, message);
        this.requestId = requestId;
    }

    public RequestNotFoundException(RequestId requestId, String message, Throwable cause) {
        super(Response.Status.NOT_FOUND, message, cause);
        this.requestId = requestId;
    }

    public RequestNotFoundException(Data data) {
        super(data);
        requestId = new RequestId(data.getAttribute("requestId"));
    }

    public Data getData() {
        Data data = super.getData();
        data.setAttribute("requestId", requestId.toString());
        return data;
    }

    public RequestId getRequestId() {
        return requestId;
    }

    public void setRequestId(RequestId requestId) {
        this.requestId = requestId;
    }
}
