package com.netscape.certsrv.system;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.DataCollection;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TPSConnectorCollection extends DataCollection<TPSConnectorData> {

    @Override
    public Collection<TPSConnectorData> getEntries() {
        return super.getEntries();
    }
}
