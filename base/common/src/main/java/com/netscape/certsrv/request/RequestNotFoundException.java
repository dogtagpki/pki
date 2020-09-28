package com.netscape.certsrv.request;

import com.netscape.certsrv.base.ResourceNotFoundException;

public class RequestNotFoundException extends ResourceNotFoundException {

    private static final long serialVersionUID = -4784839378360933483L;

    public RequestId requestId;

    public RequestNotFoundException(RequestId requestId) {
        this(requestId, "Request ID "+requestId.toHexString()+" not found");
    }

    public RequestNotFoundException(RequestId requestId, String message) {
        super(message);
        this.requestId = requestId;
    }

    public RequestNotFoundException(RequestId requestId, String message, Throwable cause) {
        super(message, cause);
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
