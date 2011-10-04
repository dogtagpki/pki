/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA 
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#ifndef __WASP_SERVER_HEADER_PROCESSOR_H
#define __WASP_SERVER_HEADER_PROCESSOR_H

#ifdef HAVE_CONFIG_H
#ifndef AUTOTOOLS_CONFIG_H
#define AUTOTOOLS_CONFIG_H

/* Eliminate warnings when using Autotools */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <config.h>
#endif /* AUTOTOOLS_CONFIG_H */
#endif /* HAVE_CONFIG_H */

#include <waspc/config/config.h>
#include <waspc/util/exceptions.h>
#include <waspc/xmlprotocol/header/HeaderProcessor.h>

class ServerHeaderProcessorItemConfiguration;

/**
 * Creates WS-Security header with a session token
 */
class EXPORT_DECL ServerHeaderProcessor : public WASP_HeaderProcessor {
protected:
    virtual ~ServerHeaderProcessor();
public:
    ServerHeaderProcessor();

    //inherited methods from WASP_Configurable
    virtual void load (WASP_Configuration *, EXCENV_DECL);
    virtual void init (EXCENV_DECL);
    virtual void destroy ();

    //inherited from WASP_HeaderProcessor    
    virtual void processInput(WASP_XMLProtocolMessage *message, EXCENV_DECL);
    virtual void processOutput(WASP_XMLProtocolMessage *message, EXCENV_DECL);
    virtual void processInputFault(WASP_XMLProtocolMessage *message, EXCENV_DECL);
    virtual void processOutputFault(WASP_XMLProtocolMessage *message, EXCENV_DECL);
    virtual WASP_String **getUnderstandHeaders(int &count, EXCENV_DECL);

protected:
    WASP_String **mppsUnderstandHeaderNamesAndNs;
    int miUnderstandHeaderCount;
};

#endif //__WASP_SERVER_HEADER_PROCESSOR_H
