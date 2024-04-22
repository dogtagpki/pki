//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.dbs;

/**
 * This exception indicates that a record already exists in the internal database.
 */
public class DBRecordAlreadyExistsException extends DBException {

    private static final long serialVersionUID = 1L;

    public DBRecordAlreadyExistsException(String errorString) {
        super(errorString);
    }

    public DBRecordAlreadyExistsException(String errorString, Throwable cause) {
        super(errorString, cause);
    }
}
