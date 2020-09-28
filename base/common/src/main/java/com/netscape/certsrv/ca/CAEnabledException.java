package com.netscape.certsrv.ca;

/**
 * Exception to throw when an operation cannot be performed because
 * the CA to which the operation pertains is enabled.
 */
public class CAEnabledException extends ECAException {

    private static final long serialVersionUID = 1056602856006912665L;

    public CAEnabledException(String msgFormat) {
        super(msgFormat);
    }

}
