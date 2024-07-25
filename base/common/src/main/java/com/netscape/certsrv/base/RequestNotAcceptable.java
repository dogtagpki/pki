//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class RequestNotAcceptable extends PKIException {

    private static final long serialVersionUID = 1L;

    public RequestNotAcceptable(String message) {
        super(Response.Status.NOT_ACCEPTABLE, message);
    }

    public RequestNotAcceptable(String message, Throwable cause) {
        super(Response.Status.NOT_ACCEPTABLE, message, cause);
    }

    public RequestNotAcceptable(Data data) {
        super(data);
    }

}
