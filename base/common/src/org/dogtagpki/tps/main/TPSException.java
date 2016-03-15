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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.tps.main;

import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

import com.netscape.certsrv.base.EBaseException;

public class TPSException extends EBaseException {

    private static final long serialVersionUID = -678878301521643436L;
    private TPSStatus status;

    public TPSException(String message) {
        super(message);
        status = TPSStatus.STATUS_ERROR_CONTACT_ADMIN;
    }

    public TPSException(String message, TPSStatus status) {
        super(message);
        this.status = status;
    }

    public TPSException(Throwable cause) {
        super(cause.getMessage(), cause);
        status = TPSStatus.STATUS_ERROR_CONTACT_ADMIN;
    }

    public TPSException(String message, Throwable cause) {
        super(message, cause);
        status = TPSStatus.STATUS_ERROR_CONTACT_ADMIN;
    }

    public TPSException(String message, TPSStatus status, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public TPSStatus getStatus() {
        return status;
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
