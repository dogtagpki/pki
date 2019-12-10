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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;

import netscape.ldap.LDAPConnection;

public class ReplicationUtil {

    public final static Logger logger = LoggerFactory.getLogger(ReplicationUtil.class);

    public static void setupReplication(
            LDAPConfigurator masterConfigurator,
            LDAPConfigurator replicaConfigurator,
            String replica_replicationpwd,
            int masterReplicationPort,
            int cloneReplicationPort,
            String replicationSecurity) throws Exception {

        logger.info("ReplicationUtil: setting up replication");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();
        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        LDAPConfig masterCfg = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
        LDAPConnectionConfig masterConnCfg = masterCfg.getConnectionConfig();

        LDAPConfig replicaCfg = cs.getInternalDBConfig();
        LDAPConnectionConfig replicaConnCfg = replicaCfg.getConnectionConfig();

        String machinename = cs.getHostname();
        String instanceId = cs.getInstanceID();

        String master_hostname = masterConnCfg.getString("host", "");
        String master_replicationpwd = preopConfig.getString("internaldb.master.replication.password", "");

        String replica_hostname = replicaConnCfg.getString("host", "");

        String basedn = replicaCfg.getBaseDN();
        String suffix = replicaCfg.getBaseDN();

        String masterAgreementName = "masterAgreement1-" + machinename + "-" + instanceId;
        String cloneAgreementName = "cloneAgreement1-" + machinename + "-" + instanceId;

        LDAPConnection masterConn = masterConfigurator.getConnection();
        LDAPConnection replicaConn = replicaConfigurator.getConnection();

        try {
            String replicadn = "cn=replica,cn=\"" + suffix + "\",cn=mapping tree,cn=config";
            logger.debug("ReplicationUtil: replica DN: " + replicadn);

            String masterBindUser = "Replication Manager " + masterAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on master");
            masterConfigurator.createSystemContainer();
            masterConfigurator.createReplicationManager(masterBindUser, master_replicationpwd);

            String masterChangelog = masterConfigurator.getInstanceDir() + "/changelogs";
            logger.debug("ReplicationUtil: creating master changelog dir: " + masterChangelog);
            masterConfigurator.createChangeLog(masterChangelog);

            String cloneBindUser = "Replication Manager " + cloneAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on replica");
            replicaConfigurator.createSystemContainer();
            replicaConfigurator.createReplicationManager(cloneBindUser, replica_replicationpwd);

            String replicaChangelog = replicaConfigurator.getInstanceDir() + "/changelogs";
            logger.debug("ReplicationUtil: creating replica changelog dir: " + masterChangelog);
            replicaConfigurator.createChangeLog(replicaChangelog);

            int replicaId = dbConfig.getInteger("beginReplicaNumber", 1);

            logger.debug("ReplicationUtil: enabling replication on master");
            replicaId = masterConfigurator.enableReplication(replicadn, masterBindUser, basedn, replicaId);

            logger.debug("ReplicationUtil: enabling replication on replica");
            replicaId = replicaConfigurator.enableReplication(replicadn, cloneBindUser, basedn, replicaId);

            logger.debug("ReplicationUtil: replica ID: " + replicaId);
            dbConfig.putString("beginReplicaNumber", Integer.toString(replicaId));

            logger.debug("ReplicationUtil: creating master replication agreement");
            masterConfigurator.createReplicationAgreement(
                    replicadn,
                    masterAgreementName,
                    replica_hostname,
                    cloneReplicationPort,
                    replica_replicationpwd,
                    basedn,
                    cloneBindUser,
                    replicationSecurity);

            logger.debug("ReplicationUtil: creating replica replication agreement");
            replicaConfigurator.createReplicationAgreement(
                    replicadn,
                    cloneAgreementName,
                    master_hostname,
                    masterReplicationPort,
                    master_replicationpwd,
                    basedn,
                    masterBindUser,
                    replicationSecurity);

            logger.debug("ReplicationUtil: initializing replication consumer");
            masterConfigurator.initializeConsumer(replicadn, masterAgreementName);

        } catch (Exception e) {
            logger.error("ReplicationUtil: Unable to setup replication: " + e.getMessage(), e);
            throw new IOException("Unable to setup replication: " + e.getMessage(), e);
        }
    }
}
