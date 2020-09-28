package com.netscape.certsrv.ca;

/**
 * Exception to throw when a (sub-)CA's signing key is not (yet)
 * present in the local NSSDB.
 */
public class CAMissingKeyException extends ECAException {

    private static final long serialVersionUID = -364157165997677925L;

    public CAMissingKeyException(String msgFormat) {
        super(msgFormat);
    }

    public CAMissingKeyException(String msgFormat, Exception cause) {
        super(msgFormat, cause);
    }
}
