package com.netscape.certsrv.ca;

/**
 * Exception to throw when a (sub-)CA cannot perform an operation
 * because it is disabled.
 */
public class CADisabledException extends ECAException {

    private static final long serialVersionUID = -8827509070155037699L;

    public CADisabledException(String msgFormat) {
        super(msgFormat);
    }

}
