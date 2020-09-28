package com.netscape.certsrv.ca;

/**
 * Exception to throw when an operation cannot be completed
 * because the CA is the wrong type (e.g., an operation that
 * only applies to lightweight CAs).
 */
public class CATypeException extends ECAException {

    private static final long serialVersionUID = -6004456461295692150L;

    public CATypeException(String msgFormat) {
        super(msgFormat);
    }

}
