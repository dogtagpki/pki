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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging;

public enum LogSource {
    ALL                 (0),
    KRA                 (1),
    RA                  (2),
    CA                  (3),
    HTTP                (4),
    DB                  (5),
    AUTHENTICATION      (6),
    ADMIN               (7),
    LDAP                (8),
    REQQUEUE            (9),
    ACLS                (10),
    USRGRP              (11),
    OCSP                (12),
    AUTHORIZATION       (13),
    SIGNED_AUDIT        (14),
    XCERT               (15),
    TKS                 (16),
    TPS                 (17),
    OTHER               (20);

    private final int value;

    LogSource(int value) {
        this.value = value;
    }

    public int value() {
        return value;
    }

    public static LogSource valueOf(int value) {
        for (LogSource s : LogSource.values()) {
            if (s.value == value) {
                return s;
            }
        }
        return null;
    }
}
