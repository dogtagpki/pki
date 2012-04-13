/**
 * 
 */
package com.netscape.cms.servlet.csadmin.model;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement
public class SecurityDomainHostList {
    protected Collection<SecurityDomainHost> systems;
    
    @XmlElement(name="SubsystemCount")
    protected int count;

    /**
     * @return the systems
     */
    @XmlElementRef
    public Collection<SecurityDomainHost> getSystems() {
        return systems;
    }

    /**
     * @param systems the systems to set
     */
    public void setSystems(Collection<SecurityDomainHost> systems) {
        this.systems = systems;
    }

    /**
     * @return the count
     */
    public int getCount() {
        return count;
    }

    /**
     * @param count the count to set
     */
    public void setCount(int count) {
        this.count = count;
    }
    
    
}
