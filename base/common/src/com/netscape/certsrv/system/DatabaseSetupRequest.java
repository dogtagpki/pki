// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="DatabaseSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class DatabaseSetupRequest {

    @XmlElement
    protected String pin;

    @XmlElement
    protected String createDatabase;

    @XmlElement
    protected String reindexDatabase;

    @XmlElement(defaultValue="false")
    protected String isClone;

    @XmlElement
    protected String masterReplicationPort;

    @XmlElement
    protected String cloneReplicationPort;

    @XmlElement
    protected String setupReplication;

    @XmlElement
    protected String replicateSchema;

    @XmlElement
    protected String replicationSecurity;

    public DatabaseSetupRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public boolean getCreateDatabase() {
        return createDatabase != null && createDatabase.equalsIgnoreCase("true");
    }

    public void setCreateDatabase(String createDatabase) {
        this.createDatabase = createDatabase;
    }

    public boolean getReindexDatabase() {
        return reindexDatabase != null && reindexDatabase.equalsIgnoreCase("true");
    }

    public void setReindexDatabase(String reindexDatabase) {
        this.reindexDatabase = reindexDatabase;
    }

    public boolean isClone() {
        return (isClone!= null) && isClone.equalsIgnoreCase("true");
    }

    public void setClone(String isClone) {
        this.isClone = isClone;
    }

    /**
     * @return the masterReplicationPort
     */
    public String getMasterReplicationPort() {
        return masterReplicationPort;
    }

    /**
     * @param masterReplicationPort the masterReplicationPort to set
     */
    public void setMasterReplicationPort(String masterReplicationPort) {
        this.masterReplicationPort = masterReplicationPort;
    }

    /**
     * @return the cloneReplicationPort
     */
    public String getCloneReplicationPort() {
        return cloneReplicationPort;
    }

    /**
     * @param cloneReplicationPort the cloneReplicationPort to set
     */
    public void setCloneReplicationPort(String cloneReplicationPort) {
        this.cloneReplicationPort = cloneReplicationPort;
    }

    public boolean getSetupReplication() {
        return setupReplication != null && setupReplication.equalsIgnoreCase("true");
    }

    public void setSetupReplication(String setupReplication) {
        this.setupReplication = setupReplication;
    }

    /**
     * @return the replicationSecurity
     */
    public String getReplicationSecurity() {
        return replicationSecurity;
    }

    /**
     * @param replicationSecurity the replicationSecurity to set
     */
    public void setReplicationSecurity(String replicationSecurity) {
        this.replicationSecurity = replicationSecurity;
    }

    public boolean getReplicateSchema() {
        return replicateSchema != null && replicateSchema.equalsIgnoreCase("true");
    }

    public void setReplicateSchema(String replicateSchema) {
        this.replicateSchema = replicateSchema;
    }

    @Override
    public String toString() {
        return "DatabaseSetupRequest [pin=XXXX" +
               ", createDatabase=" + createDatabase +
               ", isClone=" + isClone +
               ", masterReplicationPort=" + masterReplicationPort +
               ", cloneReplicationPort=" + cloneReplicationPort +
               ", setupReplication=" + setupReplication +
               ", replicationSecurity=" + replicationSecurity +
               ", replicateSchema=" + replicateSchema +
               "]";
    }
}
