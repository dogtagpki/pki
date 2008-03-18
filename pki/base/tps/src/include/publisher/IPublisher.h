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

#ifndef __IPUBLISHER_H__
#define __IPUBLISHER_H__

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

#if !defined (IPUBLISHER_H)

#define IPUBLISHER_H 

#include "IConnector.h"

class IPublisher
{

public:

  virtual ~IPublisher() {
      if( m_connector != NULL ) {
          delete m_connector;
          m_connector = NULL;
      }
  };
  virtual int init(void) = 0;

  virtual int publish(unsigned char *cuid, int cuid_len,long key_type,unsigned char * public_key,int public_key_len,
                     unsigned long cert_activate_date,unsigned long  cert_expire_date,unsigned long applet_version,unsigned long applet_version_date)= 0;

  IConnector *getConnector() { return m_connector;}

protected:

   IConnector * m_connector;


};

#endif

#endif /* __IPUBLISHER_H__ */

