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



#ifndef OPT_INCLUDE_H
#define OPT_INCLUDE_H

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

struct option {
  struct option *next;
  char *name;
  char *value;
};

typedef struct option OPTION;

/* OPT_getValue(char *option, char** output)

   returns 1 if the specified option exists,
      - value is put into 'output'
   returns 0 if the specified option doesn't exist
      - output is unchanged

   'value' will be everything after the '='
   If no '=' is present in the argument, 'output' will be
   set to null.
   If '=' is present, but no value is given (e.g. "file="),
   output will be a pointer to a string of zero length.

*/

extern int OPT_getValue(char *option, char **output);

/* void OPT_parseOptions(int ac, char **av)
   
   initializes the global store with the options supplied
   in av (typically used for parsing arguments passed on the
   command line. Arguments are of the form 'arg=value'.
   valid: array of valid arguments (can be null)

   returns:
   NULL if no error
   char* with error text if error. caller is responsible for
      freeing this memory
   


*/

extern char * OPT_parseOptions(int ac, char **av, char**valid);

#endif
