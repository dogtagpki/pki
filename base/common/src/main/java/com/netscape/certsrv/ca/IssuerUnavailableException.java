package com.netscape.certsrv.ca;

/**
 * Exception to throw during CA creation when requested CA
 * (issuer DN) already exists.
 */
public class IssuerUnavailableException extends ECAException {

    private static final long serialVersionUID = -6247493607604418446L;

    public IssuerUnavailableException(String msgFormat) {
        super(msgFormat);
    }

}
