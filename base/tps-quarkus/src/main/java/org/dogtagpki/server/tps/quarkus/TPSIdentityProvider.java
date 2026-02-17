//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.dogtagpki.server.quarkus.PKIIdentityProvider;

import com.netscape.cmscore.apps.CMSEngine;

@ApplicationScoped
public class TPSIdentityProvider extends PKIIdentityProvider {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getDefaultRole() {
        return "TPS Agents";
    }
}
