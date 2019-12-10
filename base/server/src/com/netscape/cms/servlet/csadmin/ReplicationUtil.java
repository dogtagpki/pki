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

public class ReplicationUtil {

    public final static Logger logger = LoggerFactory.getLogger(ReplicationUtil.class);

    public static void setupReplication(
            LDAPConfigurator masterConfigurator,
            LDAPConfigurator replicaConfigurator,
            String masterReplicationPassword,
            String replicaReplicationPassword,
            int masterReplicationPort,
            int replicaReplicationPort,
            String replicationSecurity) throws Exception {

        logger.info("ReplicationUtil: setting up replication");

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();
        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        String hostname = cs.getHostname();
        String instanceID = cs.getInstanceID();

        LDAPConfig masterCfg = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
        LDAPConnectionConfig masterConnCfg = masterCfg.getConnectionConfig();

        LDAPConfig replicaConfig = cs.getInternalDBConfig();
        LDAPConnectionConfig replicaConnCfg = replicaConfig.getConnectionConfig();

        String baseDN = replicaConfig.getBaseDN();

        String masterHostname = masterConnCfg.getString("host", "");
        String replicaHostname = replicaConnCfg.getString("host", "");

        String masterAgreementName = "masterAgreement1-" + hostname + "-" + instanceID;
        String replicaAgreementName = "cloneAgreement1-" + hostname + "-" + instanceID;

        try {
            String replicaDN = "cn=replica,cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
            logger.debug("ReplicationUtil: replica DN: " + replicaDN);

            String masterBindUser = "Replication Manager " + masterAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on master");
            masterConfigurator.createSystemContainer();
            masterConfigurator.createReplicationManager(masterBindUser, masterReplicationPassword);

            String masterChangelog = masterConfigurator.getInstanceDir() + "/changelogs";
            logger.debug("ReplicationUtil: creating master changelog dir: " + masterChangelog);
            masterConfigurator.createChangeLog(masterChangelog);

            String replicaBindUser = "Replication Manager " + replicaAgreementName;
            logger.debug("ReplicationUtil: creating replication manager on replica");
            replicaConfigurator.createSystemContainer();
            replicaConfigurator.createReplicationManager(replicaBindUser, replicaReplicationPassword);

            String replicaChangelog = replicaConfigurator.getInstanceDir() + "/changelogs";
            logger.debug("ReplicationUtil: creating replica changelog dir: " + masterChangelog);
            replicaConfigurator.createChangeLog(replicaChangelog);

            int replicaID = dbConfig.getInteger("beginReplicaNumber", 1);

            logger.debug("ReplicationUtil: enabling replication on master");
            replicaID = masterConfigurator.enableReplication(replicaDN, masterBindUser, baseDN, replicaID);

            logger.debug("ReplicationUtil: enabling replication on replica");
            replicaID = replicaConfigurator.enableReplication(replicaDN, replicaBindUser, baseDN, replicaID);

            logger.debug("ReplicationUtil: replica ID: " + replicaID);
            dbConfig.putString("beginReplicaNumber", Integer.toString(replicaID));

            logger.debug("ReplicationUtil: creating master replication agreement");
            masterConfigurator.createReplicationAgreement(
                    replicaDN,
                    masterAgreementName,
                    replicaHostname,
                    replicaReplicationPort,
                    replicaReplicationPassword,
                    baseDN,
                    replicaBindUser,
                    replicationSecurity);

            logger.debug("ReplicationUtil: creating replica replication agreement");
            replicaConfigurator.createReplicationAgreement(
                    replicaDN,
                    replicaAgreementName,
                    masterHostname,
                    masterReplicationPort,
                    masterReplicationPassword,
                    baseDN,
                    masterBindUser,
                    replicationSecurity);

            logger.debug("ReplicationUtil: initializing replication consumer");
            masterConfigurator.initializeConsumer(replicaDN, masterAgreementName);

        } catch (Exception e) {
            logger.error("ReplicationUtil: Unable to setup replication: " + e.getMessage(), e);
            throw new IOException("Unable to setup replication: " + e.getMessage(), e);
        }
    }
}
