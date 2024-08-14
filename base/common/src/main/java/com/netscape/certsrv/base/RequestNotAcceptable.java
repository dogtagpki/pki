//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class RequestNotAcceptable extends PKIException {

    private static final long serialVersionUID = 1L;

    public RequestNotAcceptable(String message) {
        super(HttpServletResponse.SC_NOT_ACCEPTABLE, message);
    }

    public RequestNotAcceptable(String message, Throwable cause) {
        super(HttpServletResponse.SC_NOT_ACCEPTABLE, message, cause);
    }

    public RequestNotAcceptable(Data data) {
        super(data);
    }

}
