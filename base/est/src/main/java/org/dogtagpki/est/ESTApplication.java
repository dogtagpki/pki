//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

import org.dogtagpki.server.rest.v1.PKIExceptionMapper;

@ApplicationPath("/v1")
public class ESTApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ESTApplication.class);

    private Set<Class<?>> classes = new LinkedHashSet<>();
    private Set<Object> singletons = new LinkedHashSet<>();

    public ESTApplication() {
        logger.info("Initializing ESTApplication");
        classes.add(ESTFrontend.class);

        // exception mapper
        classes.add(PKIExceptionMapper.class);

        singletons.add(new HandleBadAcceptHeaderRequestFilter());
        singletons.add(new ReformatContentTypeResponseFilter());
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

}
