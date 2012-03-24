/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */

#include "tkstool.h"

void
TKS_Version( char *progName )
{
#if defined(TKSTOOL_VERSION_SUFFIX)
    if( TKSTOOL_VERSION_SUFFIX != NULL &&
        PL_strcmp( TKSTOOL_VERSION_SUFFIX, "" ) != 0 ) {
        PR_fprintf( PR_STDOUT,
                    "%s:  Version %d.%d %s\n",
                    progName,
                    TKSTOOL_MAJOR_VERSION_NUMBER,
                    TKSTOOL_MINOR_VERSION_NUMBER,
                    TKSTOOL_VERSION_SUFFIX );
    } else {
        PR_fprintf( PR_STDOUT,
                    "%s:  Version %d.%d\n",
                    progName,
                    TKSTOOL_MAJOR_VERSION_NUMBER,
                    TKSTOOL_MINOR_VERSION_NUMBER );
    }
#else
    PR_fprintf( PR_STDOUT,
                "%s:  Version %d.%d\n",
                progName,
                TKSTOOL_MAJOR_VERSION_NUMBER,
                TKSTOOL_MINOR_VERSION_NUMBER );
#endif
}

