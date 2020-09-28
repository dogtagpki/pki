package com.netscape.certsrv.ca;

/**
 * Exception to throw when an operation cannot be performed because
 * the CA to which the operation pertains is not a leaf CA (ie, has
 * sub-CAs).
 */
public class CANotLeafException extends ECAException {

    private static final long serialVersionUID = -2729093578678941399L;

    public CANotLeafException(String msgFormat) {
        super(msgFormat);
    }

}
