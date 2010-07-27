/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2009 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef AUDIT_H
#define AUDIT_H

#define AUDIT_SIG_MSG_FORMAT "[%s] %x [AuditEvent=%s][SubjectID=%s][Outcome=%s] signature of audit buffer just flushed: sig: %s"
#define AUDIT_MSG_FORMAT "[SubjectID=%s][Outcome=%s] %s"

// for EV_ROLE_ASSUME
#define AUDIT_MSG_ROLE "[SubjectID=%s][Role=%s][Outcome=%s] %s" 

// for EV_CONFIG, EV_CONFIG_ROLE, EV_CONFIG_TOKEN, EV_CONFIG_PROFILE, EV_CONFIG_AUDIT
/*
 ParamNameValPairs must be a name;;value pair
    (where name and value are separated by the delimiter ;;)
    separated by + (if more than one name;;value pair) of config params changed
 Object which identifies the object being modified has the same format name;;value eg. tokenid;;12345
*/
#define AUDIT_MSG_CONFIG "[SubjectID=%s][Role=%s][Outcome=%s][Object=%s][ParamNameValPairs=%s] %s" 

// for EV_APPLET_UPGRADE; note: "op" is operation such as "format," "enrollment"
#define AUDIT_MSG_APPLET_UPGRADE "[SubjectID=%s][CUID=%s][MSN=%s][Outcome=%s][op=%s][KeyVersion=%s][OldAppletVersion=%s][NewAppletVersion=%s] %s"

// for EV_KEY_CHANGEOVER; note: "op" is operation such as "format," "enrollment," "pinReset," "renewal"
#define AUDIT_MSG_KEY_CHANGEOVER "[SubjectID=%s][CUID=%s][MSN=%s][Outcome=%s][op=%s][AppletVersion=%s][OldKeyVersion=%s][NewKeyVersion=%s] %s" 

// for EV_AUTH_SUCCESS and EV_AUTH_FAIL
#define AUDIT_MSG_AUTH "[SubjectID=%s][AuthID=%s][Outcome=%s] %s"

// for EV_AUTHZ_SUCCESS and EV_AUTHZ_FAIL
#define AUDIT_MSG_AUTHZ "[SubjectID=%s][op=%s][Outcome=%s] %s"

// for op's EV_FORMAT, EV_ENROLLMENT, EV_PIN_RESET, EV_RENEWAL
#define AUDIT_MSG_PROC "[SubjectID=%s][CUID=%s][MSN=%s][Outcome=%s][op=%s][AppletVersion=%s][KeyVersion=%s] %s" 

// for op's EV_ENROLLMENT and EV_RENEWAL.  
#define AUDIT_MSG_PROC_CERT_REQ "[SubjectID=%s][CUID=%s][MSN=%s][Outcome=%s][op=%s][AppletVersion=%s][KeyVersion=%s][Serial=%s][CA_ID=%s] %s" 

// op is either "revoke" or "unrevoke"
#define AUDIT_MSG_CERT_STATUS_CHANGE "[SubjectID=%s][Outcome=%s][op=%s][Serial=%s][CA_ID=%s] %s" 

/*
 * Audit events definitions
 */
#define EV_AUDIT_LOG_STARTUP "AUDIT_LOG_STARTUP"
#define EV_AUDIT_LOG_SHUTDOWN "AUDIT_LOG_SHUTDOWN"
#define EV_ROLE_ASSUME "ROLE_ASSUME"
#define EV_ENROLLMENT "ENROLLMENT"
#define EV_PIN_RESET "PIN_RESET"
#define EV_FORMAT "FORMAT"
#define EV_AUTHZ_FAIL "AUTHZ_FAIL"
#define EV_AUTHZ_SUCCESS "AUTHZ_SUCCESS"

// config operations from the TUS interface
#define EV_CONFIG "CONFIG" // for config operations not specifically defined below
#define EV_CONFIG_ROLE "CONFIG_ROLE" 
#define EV_CONFIG_TOKEN "CONFIG_TOKEN"
#define EV_CONFIG_PROFILE "CONFIG_PROFILE"
#define EV_CONFIG_AUDIT "CONFIG_AUDIT"

#define EV_APPLET_UPGRADE "APPLET_UPGRADE"
#define EV_KEY_CHANGEOVER "KEY_CHANGEOVER"

#define EV_RENEWAL "RENEWAL"

// authentication for both user login for token ops and role user login (this is different from EV_AUTHZ which is for role authorization)
#define EV_AUTH_SUCCESS "AUTH_SUCCESS"
#define EV_AUTH_FAIL "AUTH_FAIL"

#endif //AUDIT_H
