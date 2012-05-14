package com.netscape.certsrv.base;

public class BadRequestDataException extends EBaseException {

    private static final long serialVersionUID = -8401421856920994265L;


    public BadRequestDataException(String msgFormat) {
        super(msgFormat);
    }

    public BadRequestDataException(String msgFormat, Exception param) {
        super(msgFormat, param);
    }

    public BadRequestDataException(String msgFormat, Object[] params) {
        super(msgFormat, params);
    }

    public BadRequestDataException(String msgFormat, String param) {
        super(msgFormat, param);
    }

}
