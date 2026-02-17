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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Container-agnostic interface for resolving PKI instance configuration.
 *
 * This abstraction decouples the PKI engine from Tomcat's catalina.base
 * system property, allowing the same business logic to run under
 * different application containers (Tomcat, Quarkus, etc.).
 */
public interface InstanceConfig {

    /**
     * Returns the absolute path to the PKI instance directory.
     *
     * For Tomcat deployments this corresponds to catalina.base.
     * For Quarkus deployments this is read from pki.instance.dir.
     */
    String getInstanceDir();

    /**
     * Returns the instance identifier (the last path component
     * of the instance directory).
     */
    default String getInstanceID() {
        Path instancePath = Paths.get(getInstanceDir());
        return instancePath.getFileName().toString();
    }
}
