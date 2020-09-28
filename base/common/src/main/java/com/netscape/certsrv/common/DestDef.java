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
 * This interface defines all the operation destination
 * used in the administration protocol between the
 * console and the server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public interface DestDef {

    public final static String DEST_CA_ADMIN = "caadmin";
    public final static String DEST_OCSP_ADMIN = "ocsp";
    public final static String DEST_RA_ADMIN = "ra";
    public final static String DEST_KRA_ADMIN = "kra";
    public final static String DEST_CA_SERVLET_ADMIN = "caservlet";
    public final static String DEST_KRA_SERVLET_ADMIN = "kraservlet";
    public final static String DEST_RA_SERVLET_ADMIN = "raservlet";
    public final static String DEST_REGISTRY_ADMIN = "registry";
    public final static String DEST_CA_PROFILE_ADMIN = "caprofile";
    public final static String DEST_RA_PROFILE_ADMIN = "raprofile";
    public final static String DEST_CA_POLICY_ADMIN = "capolicy";
    public final static String DEST_RA_POLICY_ADMIN = "rapolicy";
    public final static String DEST_KRA_POLICY_ADMIN = "krapolicy";
    public final static String DEST_LOG_ADMIN = "log";
    public final static String DEST_GROUP_ADMIN = "ug";
    public final static String DEST_USER_ADMIN = "ug";
    public final static String DEST_AUTH_ADMIN = "auths";
    public final static String DEST_JOBS_ADMIN = "jobsScheduler";
    public final static String DEST_NOTIFICATION_ADMIN = "notification";
    public final static String DEST_SERVER_ADMIN = "server";
    public final static String DEST_ACL_ADMIN = "acl";
    public final static String DEST_CA_PUBLISHER_ADMIN = "capublisher";
    public final static String DEST_RA_PUBLISHER_ADMIN = "rapublisher";
    public final static String DEST_CA_MAPPER_ADMIN = "camapper";
    public final static String DEST_RA_MAPPER_ADMIN = "ramapper";
    public final static String DEST_CA_RULE_ADMIN = "carule";
    public final static String DEST_RA_RULE_ADMIN = "rarule";
}
