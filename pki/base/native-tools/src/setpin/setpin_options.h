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


#ifndef SETPIN_OPTIONS_H
#define SETPIN_OPTIONS_H

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

extern char *o_certdb,*o_nickname,*o_binddn,*o_bindpw,*o_bindpwfile,*o_filter,*o_ssl,
  *o_input,*o_basedn,*o_dnfile,*o_host,*o_port,*o_length,*o_minlength,
  *o_maxlength,*o_gen,*o_case,*o_attribute,*o_hash,*o_objectclass,*o_output,
  *o_retry,*o_debug,*o_write,*o_clobber,*o_saltattribute,*o_testpingen,*o_setup,
  *o_pinmanager,*o_pinmanagerpwd,*o_schemachange;

extern char *valid_args[];

extern void setDefaultOptions();
extern void getOptions();
extern void validateOptions();

extern int i_length, i_minlength, i_maxlength;

extern char* attribute;

#endif
