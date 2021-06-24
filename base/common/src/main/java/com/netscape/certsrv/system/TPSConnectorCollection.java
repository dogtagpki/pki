package com.netscape.certsrv.system;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.DataCollection;

@XmlRootElement(name="TPSConnectors")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TPSConnectorCollection extends DataCollection<TPSConnectorData> {

    @Override
    @XmlElementRef
    public Collection<TPSConnectorData> getEntries() {
        return super.getEntries();
    }
}
