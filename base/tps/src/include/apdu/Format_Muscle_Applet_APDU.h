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

#ifndef FORMAT_MUSCLE_APPLET_APDU_H
#define FORMAT_MUSCLE_APPLET_APDU_H

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

#include "main/Base.h"
#include "apdu/APDU.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

class Format_Muscle_Applet_APDU : public APDU
{
  public:
	TPS_PUBLIC Format_Muscle_Applet_APDU(unsigned short memSize, 
			Buffer &PIN0, BYTE pin0Tries, 
			Buffer &unblockPIN0, BYTE unblock0Tries, 
			Buffer &PIN1, BYTE pin1Tries, 
			Buffer &unblockPIN1, BYTE unblock1Tries, 
			unsigned short objCreationPermissions, 
			unsigned short keyCreationPermissions, 
			unsigned short pinCreationPermissions);
	TPS_PUBLIC ~Format_Muscle_Applet_APDU();
	TPS_PUBLIC APDU_Type GetType();
	TPS_PUBLIC void GetEncoding(Buffer &data);
};

#endif /* FORMAT_MUSCLE_APPLET_APDU_H */
