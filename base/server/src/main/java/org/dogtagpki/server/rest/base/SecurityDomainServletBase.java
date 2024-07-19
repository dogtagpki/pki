//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.base;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class SecurityDomainServletBase {
    public static final Logger logger = LoggerFactory.getLogger(SecurityDomainServletBase.class);

    private CMSEngine engine;
    private SecurityDomainProcessor processor;

    public SecurityDomainServletBase(CMSEngine engine, Locale locale) {
        this.engine = engine;
        if (!isEnabled()) {
            logger.error("Unable to get install token: Security domain disabled");
            throw new ResourceNotFoundException("Security domain not available");
        }

        try {
            processor = new SecurityDomainProcessor(locale);
            processor.setCMSEngine(engine);
            processor.init();
        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }

    }

    public InstallToken getInstallToken(String hostname, String subsystem, String username) {
        logger.debug("SecurityDomainServletBase.getInstallToken({}, {}, {})", hostname, subsystem, username);
        try {
            return processor.getInstallToken(username, hostname, subsystem);
        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public DomainInfo getDomainInfo() {
        try {
            return processor.getDomainInfo();
        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public Collection<SecurityDomainHost> getHosts() {
        logger.debug("SecurityDomainServletBase: Getting all security domain hosts");
        try {
            Collection<SecurityDomainHost> hosts = new ArrayList<>();
            DomainInfo domainInfo = processor.getDomainInfo();
            logger.debug("SecurityDomainServletBase: domain: {}", domainInfo.getName());

            for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
                for (SecurityDomainHost host : subsystem.getHosts().values()) {
                    logger.debug("SecurityDomainServletBase: - {}", host.getId());
                    hosts.add(host);
                }
            }
            return hosts;
        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }

    }

    public SecurityDomainHost getHost(String hostId) {
        logger.debug("SecurityDomainServletBase: Getting security domain host \"{}\"", hostId);
        try {
            DomainInfo domainInfo = processor.getDomainInfo();
            logger.debug("SecurityDomainServletBase: domain: {}", domainInfo.getName());

            for (SecurityDomainSubsystem subsystem : domainInfo.getSubsystems().values()) {
                for (SecurityDomainHost host : subsystem.getHosts().values()) {

                    logger.debug("SecurityDomainServletBase: - {}", host.getId());

                    if (host.getId().equals(hostId)) {
                        logger.debug("SecurityDomainServletBase: Found security domain host {}", hostId);
                        return host;
                    }
                }
            }

            throw new ResourceNotFoundException("Security domain host not found: " + hostId);

        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void addHost(SecurityDomainHost host) {
        String hostID = host.getId();
        logger.info("SecurityDomainService: Adding security domain host \"{}\"", hostID);

        try {
            // Host ID: <type> <hostname> <port>
            Pattern pattern = Pattern.compile("^(\\S+) (\\S+) (\\d+)$");
            Matcher matcher = pattern.matcher(hostID);

            if (!matcher.find()) {
                throw new BadRequestException("Invalid security domain host: " + hostID);
            }

            String type = matcher.group(1);
            logger.debug("SecurityDomainServletBase: type: {}", type);

            String hostname = matcher.group(2);
            logger.debug("SecurityDomainServletBase: hostname: {}", hostname);

            String securePort = matcher.group(3);
            logger.debug("SecurityDomainServletBase: secure port: {}", securePort);

            String unsecurePort = host.getPort();
            logger.debug("SecurityDomainServletBase: unsecure port: {}", unsecurePort);

            String eeCAPort = host.getSecureEEClientAuthPort();
            logger.debug("SecurityDomainServletBase: secure EE port: {}", eeCAPort);

            if (!securePort.equals(eeCAPort)) {
                throw new BadRequestException("Invalid secure (EE) port: " + eeCAPort);
            }

            String adminSecurePort = host.getSecureAdminPort();
            logger.debug("SecurityDomainServletBase: secure admin port: {}", adminSecurePort);

            if (!securePort.equals(adminSecurePort)) {
                throw new BadRequestException("Invalid secure (admin) port: " + adminSecurePort);
            }

            String agentSecurePort = host.getSecureAgentPort();
            logger.debug("SecurityDomainServletBase: secure agent port: {}", agentSecurePort);

            if (!securePort.equals(agentSecurePort)) {
                throw new BadRequestException("Invalid secure (agent) port: " + agentSecurePort);
            }

            String domainManager = host.getDomainManager();
            logger.debug("SecurityDomainServletBase: domain manager: {}", domainManager);

            String clone = host.getClone();
            logger.debug("SecurityDomainServletBase: clone: {}", clone);

            String status = processor.addHost(
                    hostID,
                    type,
                    hostname,
                    securePort,
                    unsecurePort,
                    eeCAPort,
                    adminSecurePort,
                    agentSecurePort,
                    domainManager,
                    clone);
            logger.debug("SecurityDomainServletBase: status: {}", status);

            if (!SecurityDomainProcessor.SUCCESS.equals(status)) {
                throw new PKIException("Unable to add security domain host: " + hostID);
            }
        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void removeHost(String hostId) {
        logger.info("SecurityDomainServletBase: Removing security domain host \"{}\"", hostId);
        try {
            // Host ID: <type> <hostname> <port>
            Pattern pattern = Pattern.compile("^(\\S+) (\\S+) (\\d+)$");
            Matcher matcher = pattern.matcher(hostId);

            if (!matcher.find()) {
                throw new BadRequestException("Invalid security domain host: " + hostId);
            }

            String type = matcher.group(1);
            logger.debug("SecurityDomainServletBase: type: {}", type);

            String hostname = matcher.group(2);
            logger.debug("SecurityDomainServletBase: hostname: {}", hostname);

            String port = matcher.group(3);
            logger.debug("SecurityDomainServletBase: port: {}", port);

            String status = processor.removeHost(hostId, type, hostname, port);
            logger.debug("SecurityDomainServletBase: status: {}", status);

            if (!SecurityDomainProcessor.SUCCESS.equals(status)) {
                throw new PKIException("Unable to remove security domain host: " + hostId);
            }

        } catch (PKIException e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    private boolean isEnabled() {

        EngineConfig engineConfig = engine.getConfig();

        try {
            // if the server creates a new security domain (instead of joining
            // an existing one) it should provide security domain services
            String select = engineConfig.getString("securitydomain.select", "");
            return "new".equals(select);

        } catch (EBaseException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

}
