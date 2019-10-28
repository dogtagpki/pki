//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * @author Endi S. Dewata
 */
@ApplicationPath("")
public class ACMEApplication extends Application {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEApplication.class);

    private Set<Class<?>> classes = new LinkedHashSet<Class<?>>();
    private Set<Object> singletons = new LinkedHashSet<Object>();

    public ACMEApplication() {

        logger.info("Initializing ACMEApplication");

        classes.add(ACMEDirectoryService.class);
    }

    public Set<Class<?>> getClasses() {
        return classes;
    }

    public Set<Object> getSingletons() {
        return singletons;
    }
}
