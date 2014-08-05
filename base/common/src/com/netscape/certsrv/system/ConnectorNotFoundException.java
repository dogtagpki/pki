package com.netscape.certsrv.system;

import com.netscape.certsrv.base.ResourceNotFoundException;

public class ConnectorNotFoundException extends ResourceNotFoundException {

    private static final long serialVersionUID = 7542636895132507890L;

    public ConnectorNotFoundException(){
        super("Connector not found.");
    }

    public ConnectorNotFoundException(String message) {
        super(message);
    }

    public ConnectorNotFoundException(String message, Throwable reason){
        super(message, reason);
    }

    public ConnectorNotFoundException(Data data) {
        super(data);
    }

    public Data getData() {
        return super.getData();
    }

}
