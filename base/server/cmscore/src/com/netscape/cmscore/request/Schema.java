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
package com.netscape.cmscore.request;

//
// The Schema class contains constant string values for
// LDAP attribute and object class names used in this package
//
class Schema {
    public static final String LDAP_OC_TOP = "top";
    public static final String LDAP_OC_REQUEST = "request";
    public static final String LDAP_OC_EXTENSIBLE = "extensibleObject";

    public static final String LDAP_ATTR_REQUEST_ID = "requestId";
    public static final String LDAP_ATTR_REQUEST_STATE = "requestState";
    public static final String LDAP_ATTR_CREATE_TIME = "dateOfCreate";
    public static final String LDAP_ATTR_MODIFY_TIME = "dateOfModify";
    public static final String LDAP_ATTR_REQUEST_XATTRS = "adminMessages";
    public static final String LDAP_ATTR_SOURCE_ID = "requestSourceId";

    public static final String LDAP_ATTR_REQUEST_OWNER = "requestOwner";
    public static final String LDAP_ATTR_REQUEST_ATTRS = "requestAttributes";
    public static final String LDAP_ATTR_AGENT_GROUP = "requestAgentGroup";
    public static final String LDAP_ATTR_REQUEST_TYPE = "requestType";
    public static final String LDAP_ATTR_REQUEST_ERROR = "requestError";

    // This attribute is a placeholder used by ExtAttrDynMapper
    public static final String LDAP_ATTR_EXT_ATTR = "extAttr";

    // Indicates a special state that may be searched for exactly
    // such as requiresAgentService.  The idea is to reduce the space
    // used in indexes to optimize common queries.
    // NOT IMPLEMENTED
    public static final String LDAP_ATTR_REQUEST_FLAG = "requestFlag";
}
