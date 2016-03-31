package com.netscape.certsrv.ca;

/**
 * Exception to throw when a (sub-)CA's signing certificate is not
 * (yet) present in the local NSSDB.
 */
public class CAMissingCertException extends ECAException {

    private static final long serialVersionUID = 7261805480088539689L;

    public CAMissingCertException(String msgFormat) {
        super(msgFormat);
    }

}
