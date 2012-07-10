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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.common;

/**
 * This interface defines all the tasks used in
 * the configuration protocol between the
 * configuration wizard and the configuration
 * daemon.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public interface TaskId {

    // list out all the previously performed tasks
    public final static String TASK_LIST_PREVIOUS_STAGES = "listPreviousStages";

    // retrieve all information in the previously performed tasks
    public final static String TASK_GET_DEFAULT_INFO = "getStagesInfo";

    // retrieve all information to setup the wizardInfo
    public final static String TASK_SETUP_WIZARDINFO = "setupWizardInfo";

    // services to be installed: ca, kra, ra
    public final static String TASK_INSTALL_SUBSYSTEMS = "installSubsystems";

    // create the internal database
    public final static String TASK_CREATE_INTERNALDB = "createInternalDB";

    // configure network ports
    public final static String TASK_CONFIGURE_NETWORK = "configureNetwork";

    // setup certificate administrator
    public final static String TASK_SETUP_ADMINISTRATOR = "setupAdmin";

    // select subsystems
    public final static String TASK_SELECT_SUBSYSTEMS = "selectSubsystems";

    // data migration
    public final static String TASK_MIGRATION = "migration";

    // create certificate
    public final static String TASK_CREATE_CERT = "createCert";

    // kra storage key
    public final static String TASK_STORAGE_KEY = "storageKey";

    // kra agents
    public final static String TASK_AGENTS = "agents";

    // get information about all cryptotokens
    public final static String TASK_TOKEN_INFO = "tokenInfo";

    // get master or clone setting
    public final static String TASK_MASTER_OR_CLONE = "SetMasterOrClone";

    // single signon
    public final static String TASK_SINGLE_SIGNON = "singleSignon";

    // init token
    public final static String TASK_INIT_TOKEN = "initToken";

    // certificate request
    public final static String TASK_CERT_REQUEST = "certRequest";

    // certificate request submited successfully
    public final static String TASK_REQUEST_SUCCESS = "reqSuccess";

    // certificate content
    public final static String TASK_GET_CERT_CONTENT = "certContent";

    public final static String TASK_IMPORT_CERT_CHAIN = "importCertChain";

    // install certificate
    public final static String TASK_INSTALL_CERT = "installCert";

    public final static String TASK_CHECK_DN = "checkDN";

    // miscellaneous things
    public final static String TASK_MISCELLANEOUS = "doMiscStuffs";

    // validate directory manager password
    public final static String TASK_VALIDATE_DSPASSWD = "validateDSPassword";

    // set CA starting serial number
    public final static String TASK_SET_CA_SERIAL = "setCASerial";

    // set KRA request and key starting and ending number
    public final static String TASK_SET_KRA_NUMBER = "setKRANumber";

    // check key length
    public final static String TASK_CHECK_KEYLENGTH = "checkKeyLength";

    // check certificate extension
    public final static String TASK_CHECK_EXTENSION = "checkExtension";

    // check validity period: make sure the notAfterDate of the certificate
    // will not go beyond the notAfterDate of the CA cert which signs the certificate.
    public final static String TASK_VALIDITY_PERIOD = "checkValidityPeriod";

    public final static String TASK_CLONING = "taskCloning";
    public final static String TASK_CLONE_MASTER = "taskCloneMaster";

    // daemon exit
    public final static String TASK_EXIT = "exit";

    public final static String TASK_ADD_OCSP_SERVICE = "addOCSPService";

    public final static String TASK_CONFIG_WEB_SERVER = "configWebServer";

    public final static String TASK_CREATE_REPLICATION_AGREEMENT = "createReplAgreement";
    public final static String TASK_LOGON_ALL_TOKENS = "logonAllTokens";
    public final static String TASK_UPDATE_DB_INFO = "updateDBInfo";
    public final static String TASK_ADD_DBSCHEMA_INDEXES = "addDBSchemaIndexes";
}
