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
/*
 * Audit events definitions
 */
#define EV_AUDIT_LOG_STARTUP "AUDIT_LOG_STARTUP"
#define EV_AUDIT_LOG_SHUTDOWN "AUDIT_LOG_SHUTDOWN"
#define EV_ROLE_ASSUME "ROLE_ASSUME"
#define EV_ENROLLMENT "ENROLLMENT"
#define EV_PIN_RESET "PIN_RESET"
#define EV_FORMAT "FORMAT"
#define EV_UPGRADE "UPGRADE"
#define EV_AUTHZ_FAIL "AUTHZ_FAIL"
#define EV_AUTHZ_SUCCESS "AUTHZ_SUCCESS"
// ... to be continued ...

#endif //AUDIT_H
