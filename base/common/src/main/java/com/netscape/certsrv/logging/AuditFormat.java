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
package com.netscape.certsrv.logging;

/**
 * Define audit log message format. Note that the name of this
 * class "AuditFormat" is legacy and has nothing to do with the signed
 * audit log events format
 *
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class AuditFormat {

    /**
     * default log level for writing audit log
     */
    public static final int LEVEL = ILogger.LL_INFO;

    /**
     * initiative: the event is from EE
     */
    public static final String FROMUSER = "fromUser";

    /**
     * initiative: the event is from agent
     */
    public static final String FROMAGENT = "fromAgent";

    /**
     * initiative: the event is from router
     */
    public static final String FROMROUTER = "fromRouter";

    /**
     * initiative: the event is from remote authority
     */
    public static final String FROMRA = "fromRemoteAuthority";

    /**
     * authentication module: no Authentication manager
     */
    public static final String NOAUTH = "noAuthManager";

    // for ProcessCertReq.java ,kra
    /**
     * 0: request type
     * 1: request ID
     * 2: initiative
     * 3: auth module
     * 4: status
     * 5: cert dn
     * 6: other info. eg cert serial number, violation policies
     */
    public static final String FORMAT =
            "{} reqID {} {} authenticated by {} is {} DN requested: {} {}";
    public static final String NODNFORMAT =
            "{} reqID {} {} authenticated by {} is {}";

    public static final String ENROLLMENTFORMAT =
            "Enrollment request reqID {} {} authenticated by {} is {}. DN requested: {} {}";
    public static final String RENEWALFORMAT =
            "Renewal request reqID {} {} authenticated by {} is {}. DN requested: {} old serial number: 0x{} {}";
    public static final String REVOCATIONFORMAT =
            "Revocation request reqID {} {} authenticated by {} is {}. DN requested: {} serial number: 0x{} revocation reason: {} {}";

    // 1: fromAgent AgentID: xxx authenticated by xxx
    public static final String DOREVOKEFORMAT =
            "Revocation request reqID {} {} is {}. DN requested: {} serial number: 0x{} revocation reason: {}";
    // 1: fromAgent AgentID: xxx authenticated by xxx
    public static final String DOUNREVOKEFORMAT =
            "Unrevocation request reqID {} {} is {}. DN requested: {} serial number: 0x{}";

    // 0:initiative
    public static final String CRLUPDATEFORMAT =
            "CRLUpdate request {} authenticated by {} is {}. Id: {}\ncrl Number: {} last update time: {} next update time: {} number of entries in the CRL: {}";

    // audit user/group
    public static final String ADDUSERFORMAT =
            "Admin UID: {} added User UID: {}";
    public static final String REMOVEUSERFORMAT =
            "Admin UID: {} removed User UID: {} ";
    public static final String MODIFYUSERFORMAT =
            "Admin UID: {} modified User UID: {}";
    public static final String ADDUSERCERTFORMAT =
            "Admin UID: {} added cert for User UID: {}. cert DN: {} serial number: 0x{}";
    public static final String REMOVEUSERCERTFORMAT =
            "Admin UID: {} removed cert of User UID: {}. cert DN: {} serial number: 0x{}";
    public static final String ADDUSERGROUPFORMAT =
            "Admin UID: {} added User UID: {} to group: {}";
    public static final String REMOVEUSERGROUPFORMAT =
            "Admin UID: {} removed User UID: {} from group: {}";
    public static final String ADDCERTSUBJECTDNFORMAT =
            "Admin UID: {} added cert subject DN for User UID: {}. cert DN: {}";
    public static final String REMOVECERTSUBJECTDNFORMAT =
            "Admin UID: {} removed cert subject DN for User UID: {}. cert DN: {}";

    // LDAP publishing
    public static final String LDAP_PUBLISHED_FORMAT =
            "{} successfully published serial number: 0x{} with DN: {}";

}
