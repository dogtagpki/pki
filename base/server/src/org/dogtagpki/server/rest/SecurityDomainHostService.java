//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import java.util.ArrayList;
import java.util.Collection;

import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainHostResource;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;

/**
 * @author Endi S. Dewata
 */
public class SecurityDomainHostService extends PKIService implements SecurityDomainHostResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDomainHostService.class);

    @Override
    public Response getHosts() throws Exception {

        logger.info("SecurityDomainService: Getting all security domain hosts");

        Collection<SecurityDomainHost> hosts = new ArrayList<>();

        SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));

        DomainInfo domainInfo = processor.getDomainInfo();
        logger.debug("SecurityDomainService: domain: " + domainInfo.getName());

        for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
            for (SecurityDomainHost host : subsystem.getHosts().values()) {
                logger.debug("SecurityDomainService: - " + host.getId());
                hosts.add(host);
            }
        }

        GenericEntity<Collection<SecurityDomainHost>> entity =
                new GenericEntity<Collection<SecurityDomainHost>>(hosts) {};

        return createOKResponse(entity);
    }

    @Override
    public Response getHost(String hostID) throws Exception {

        logger.info("SecurityDomainService: Getting security domain host \"" + hostID + "\"");

        SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));

        DomainInfo domainInfo = processor.getDomainInfo();
        logger.debug("SecurityDomainService: domain: " + domainInfo.getName());

        for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
            for (SecurityDomainHost host : subsystem.getHosts().values()) {

                logger.debug("SecurityDomainService: - " + host.getId());

                if (host.getId().equals(hostID)) {
                    logger.debug("SecurityDomainService: Found security domain host " + hostID);
                    return createOKResponse(host);
                }
            }
        }

        throw new ResourceNotFoundException("Security domain host not found: " + hostID);
    }
}
