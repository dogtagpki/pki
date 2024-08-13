package com.netscape.certsrv.system;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TPSConnectorCollection extends DataCollection<TPSConnectorData> implements JSONSerializer{

    @Override
    public Collection<TPSConnectorData> getEntries() {
        return super.getEntries();
    }
}
