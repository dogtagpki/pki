package com.netscape.cms.servlet.request.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

import com.netscape.certsrv.request.RequestId;
@XmlAccessorType(XmlAccessType.FIELD)
public  class CMSRequestInfo {
    @XmlElement
    protected String requestType;

    @XmlElement
    protected String requestStatus;

    @XmlElement
    protected String requestURL;

    /**
     * @return the requestType
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * @param requestType the requestType to set
     */
    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    /**
     * @return the requestStatus
     */
    public String getRequestStatus() {
        return requestStatus;
    }

    /**
     * @param requestStatus the requestStatus to set
     */
    public void setRequestStatus(String requestStatus) {
        this.requestStatus = requestStatus;
    }

    /**
     * @return the requestURL
     */
    public String getRequestURL() {
        return requestURL;
    }

    /**
     * @return the request ID in the requestURL
     */
    public RequestId getRequestId() {
        String id = requestURL.substring(requestURL.lastIndexOf("/") + 1);
        return new RequestId(id);
    }

    /**
     * @param requestURL the requestURL to set
     */
    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

}
