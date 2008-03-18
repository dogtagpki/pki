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

#ifndef __NETKEY_PUBLISHER_H__
#define __NETKEY_PUBLISHER_H__

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

#if !defined (NETKEY_PUBLISHER_H)
#define NETKEY_PUBLISHER_H

#include "IPublisher.h"
class IPublisher;
class NetkeyPublisher : public IPublisher
{

public:


  NetkeyPublisher();
  ~NetkeyPublisher();

  int init(void) ;

  int publish(unsigned char *cuid, int cuid_len,long key_type,unsigned char * public_key,int public_key_len,
                      unsigned long cert_activate_date,unsigned long  cert_expire_date,unsigned long applet_version,unsigned long applet_version_date);


  static  pthread_mutex_t mutex;


};

extern "C"
{
    IPublisher *GetIPublisher();

};

#endif

#endif /* __NETKEY_PUBLISHER_H__ */

