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
TKS_Usage( char *progName )
{
    PR_fprintf( PR_STDERR,
                "Usage:  %s -D -n keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -H\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -I -n keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -K -n keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -L -d DBDir [-h all | -h token_name]\n"
                "\t\t[-p DBPrefix] [-n keyname] [-f pwfile] [-x]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -M -n keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -N -d DBDir\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -P -d DBDir\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -R -n keyname -r new_keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -S -d DBDir\n"
                "\t\t[-p DBPrefix] [-x]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -T -n keyname -d DBDir [-h token_name]\n"
                "\t\t[-p DBPrefix] [-f pwfile] [-z noisefile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -U -n keyname -d DBDir -t transport_keyname -i infile\n"
                "\t\t[-h token_name] [-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -V\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "\t%s -W -n keyname -d DBDir -t transport_keyname -o outfile\n"
                "\t\t[-h token_name] [-p DBPrefix] [-f pwfile]\n\n",
                progName );
    PR_fprintf( PR_STDERR,
                "Type \"%s -H\" for more detailed descriptions\n\n",
                progName );
}


void
TKS_PrintHelp( char *progName )
{
    /**********************/
    /* -D command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Delete a key from the token\n",
                "-D" );
    PR_fprintf( PR_STDERR,
                "%-24s The name of the key to delete\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token from which to remove key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -H command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Display this extended help for Usage\n",
                "-H" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -I command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Input shares to generate a new transport key\n",
                "-I" );
    PR_fprintf( PR_STDERR,
                "%-24s The name to assign to the generated transport key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to generate transport key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -K command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Display the KCV of the specified key\n",
                "-K" );
    PR_fprintf( PR_STDERR,
                "%-24s The name of the key to perform a KCV on\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token on which the named key resides\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -L command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s List out a specified key, or all keys\n",
                "-L" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Look on all tokens OR\n"
                "%-24s Name of token in which to look for keys\n"
                "\t\t         [optional]\n",
                "   -h all |",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s The name of the key to list\n"
                "\t\t         [optional]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "%-24s force the database to open R/W (software only)\n"
                "\t\t         [optional]\n",
                "   -x" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -M command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Generate a new master key\n",
                "-M" );
    PR_fprintf( PR_STDERR,
                "%-24s The name to assign to the generated master key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to generate master key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -N command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Create a new key database (software only)\n",
                "-N" );
    PR_fprintf( PR_STDERR,
                "%-24s Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Key database prefix (software only)\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -P command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Change the key database password (software only)\n",
                "-P" );
    PR_fprintf( PR_STDERR,
                "%-24s Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Key database prefix (software only)\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -R command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Rename a symmetric key\n",
                "-R" );
    PR_fprintf( PR_STDERR,
                "%-24s The original name assigned to a pre-existing\n"
                "\t\t         symmetric key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s The new name assigned to the original pre-existing\n"
                "\t\t         symmetric key\n"
                "\t\t         [required]\n",
                "   -r new_keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to generate master key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -S command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s List all security modules\n",
                /*, or print out a single named module\n",*/
                "-S" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s force the database to open R/W (software only)\n"
                "\t\t         [optional]\n",
                "   -x" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -T command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Generate a new transport key\n",
                "-T" );
    PR_fprintf( PR_STDERR,
                "%-24s The name to assign to the generated transport key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to generate transport key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the noise file to be used\n"
                "\t\t         [optional]\n",
                "   -z noisefile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -U command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Unwrap the wrapped master key\n",
                "-U" );
    PR_fprintf( PR_STDERR,
                "%-24s The name to assign to the unwrapped master key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s The name of the transport key (e. g. - unwrapping key)\n"
                "\t\t         [required]\n",
                "   -t transport_keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s The filename from which to input the wrapped master key\n"
                "\t\t         [required]\n",
                "   -i infile" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to store wrapped master key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -V command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Display the version number of this tool\n",
                "-V" );
    PR_fprintf( PR_STDERR,
                "\n" );


    /**********************/
    /* -W command options */
    /**********************/

    PR_fprintf( PR_STDERR,
                "%-15s Wrap a newly generated master key\n",
                "-W" );
    PR_fprintf( PR_STDERR,
                "%-24s The name to assign to the generated master key\n"
                "\t\t         [required]\n",
                "   -n keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database directory (HSM);\n"
                "\t\t         Key database directory (software only)\n"
                "\t\t         [required]\n",
                "   -d DBDir" );
    PR_fprintf( PR_STDERR,
                "%-24s The name of the transport key (e. g. - wrapping key)\n"
                "\t\t         [required]\n",
                "   -t transport_keyname" );
    PR_fprintf( PR_STDERR,
                "%-24s The filename in which to output the wrapped master key\n"
                "\t\t         [required]\n",
                "   -o outfile" );
    PR_fprintf( PR_STDERR,
                "%-24s Name of token in which to generate master key\n"
                "\t\t         [optional]\n",
                "   -h token_name" );
    PR_fprintf( PR_STDERR,
                "%-24s Security module database prefix\n"
                "\t\t         [optional]\n",
                "   -p DBPrefix" );
    PR_fprintf( PR_STDERR,
                "%-24s Specify the password file\n"
                "\t\t         [optional]\n",
                "   -f pwfile" );
    PR_fprintf( PR_STDERR,
                "\n" );
}

