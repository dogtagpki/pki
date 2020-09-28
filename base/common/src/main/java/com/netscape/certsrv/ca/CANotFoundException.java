package com.netscape.certsrv.ca;

/**
 * Exception to throw when a (sub-)CA cannot be found.
 */
public class CANotFoundException extends ECAException {

    private static final long serialVersionUID = -4618887355685066120L;

    public CANotFoundException(String msgFormat) {
        super(msgFormat);
    }

}
