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

#ifndef RA_PBLOCK_H
#define RA_PBLOCK_H

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

#include "main/Buffer.h"

#define MAX_NVS 50

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

struct Buffer_nv {
    char *name;
    char *value_s;
    Buffer *value;
};

class RA_pblock
{
    public:
        TPS_PUBLIC RA_pblock( int tm_nargs, Buffer_nv** tm_nvs );
        TPS_PUBLIC ~RA_pblock();
    public:
        Buffer_nv **GetNVs();
        TPS_PUBLIC Buffer *find_val( const char * name );
        TPS_PUBLIC char* find_val_s( const char * name );
        void free_pblock();
        TPS_PUBLIC char *get_name( int i );
        TPS_PUBLIC int get_num_of_names();
    public:
        // an array of pointers to name/value pairs
        Buffer_nv *m_nvs[MAX_NVS];
        int m_nargs;
};

#endif /* RA_PBLOCK_H */
