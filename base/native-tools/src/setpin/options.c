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



#include "options.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

/*
 * (C) 1998 Netscape Communications Corporation
 * All rights reserved
 * Intellectual property rulez!
 *
 */



/* this file maintains a static linked list of the
   options it knows about
*/

static OPTION *option_list = NULL;
static OPTION *last_option = NULL;

static char* OPT_parseArgument(char *arg,char**valid);


/* OPT_getValue(char *option, char** output)

   returns 1 if the specified option exists,
      - value is put into 'output'
   returns 0 if the specified option doesn't exist
      - output is unchanged

*/


int OPT_getValue(char *option, char **output) {
  OPTION *opt = option_list;

  while (opt) {
    if (! strcmp(opt->name,option)) {
      *output = opt->value;
      return 1;
    }
    opt = opt->next;
  }
  return 0;
}


static char* OPT_parseOptFile(char *filename, char*validlist[])
{
  FILE *fp;
  char buffer[1024];

  if (filename == NULL || filename[0] == '\0') {
     return ("Bad syntax for 'optfile'\n");
  }
  fp = fopen(filename,"r");
  if (fp == NULL) {
     return ("Options file could not be opened for reading\n");
  }
  while (fgets(buffer,1024,fp)) {
     if (buffer[strlen(buffer)-1] == '\n') buffer[strlen(buffer)-1] = '\0';
     if (buffer[strlen(buffer)-1] == '\r') buffer[strlen(buffer)-1] = '\0';

     OPT_parseArgument(strdup(buffer),validlist);
  }
  fclose(fp);
  return NULL;
}



static char *OPT_parseArgument(char *arg, char* validlist[]) {
  char *error;
  char *INV_ARG = "invalid argument: %s";
  char *eq;

  OPTION *new_opt;

  if (!strncmp(arg,"optfile=",8)) {
     return OPT_parseOptFile(&arg[8],validlist);
  }

  new_opt = (OPTION*)malloc(sizeof(OPTION));
  
  new_opt->next = NULL;
  new_opt->name = strdup(arg);
  eq = strchr(new_opt->name,'=');
  if (eq) {
    *eq = 0;
  }
  new_opt->value = strchr(arg,'=');
 

  if (new_opt->value != NULL) {
    new_opt->value++;
  }

  if (option_list == NULL) {
    option_list = new_opt;
    last_option = new_opt;
  }
  else {
    last_option->next = new_opt;
    last_option= new_opt;
  }
  if (!validlist) {
    return NULL;
  }
  else {
    int i=0;
    while (validlist[i]) {
      if (! strcmp(validlist[i],new_opt->name)) {
	return NULL;
      }
      i+=2;
    }
  }

  error = (char *)malloc(strlen(INV_ARG)+strlen(new_opt->name)+5);
  sprintf(error,INV_ARG,new_opt->name);

  return error;
}




/* char *OPT_parseOptions(int ac, char **av)
   
   constructs the linked list of options
   ac: number of arguments
   av: array of arguments
   valid: array of valid arguments (can be null)

   returns:
   NULL if no error
   char* with error text if error. caller is responsible for
      freeing this memory
   
*/

char * OPT_parseOptions(int ac, char **av, char *valid[]) {
  int i=0;
  char *r=NULL;

  assert(option_list == NULL);
  assert(last_option == NULL);
  assert(av != NULL);
  
  if (ac == 1) return NULL;
  
  for (i=0; i<ac-1; i++) {
    r = OPT_parseArgument(av[1+i],valid);
    if (r) return r;
  }
  return r;
}


  

