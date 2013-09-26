package com.netscape.certsrv.system;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.base.DataCollection;

@XmlRootElement(name="TPSConnectors")
public class TPSConnectorCollection extends DataCollection<TPSConnectorData> {

    @XmlElementRef
    public Collection<TPSConnectorData> getEntries() {
        return super.getEntries();
    }
}
