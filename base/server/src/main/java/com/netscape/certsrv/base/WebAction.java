//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.base;

import static java.lang.annotation.ElementType.METHOD;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.dogtagpki.server.rest.v2.PKIServlet;

/**
 * Implement basic routing for REST APIs
 *
 * If a servlet extends PKIServlet this annotation can specify the method to use for handle a
 * specific REST API. It has two parameter associating the HTTP operation and the path to be
 * handled by this method. The paths are relative and inside the servlet context.
 *
 *
 * @see PKIServlet
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@Target(METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface WebAction {

    PKIServlet.HttpMethod method();

    String[] paths();

}
