/** BEGIN COPYRIGHT BLOCK
 *
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 *
 * END COPYRIGHT BLOCK **/
#ifdef XP_PC

/*
**  This comes from the AT&T public-domain getopt published in mod.sources
**  (i.e., comp.sources.unix before the great Usenet renaming).
*/

#include <stdio.h>
#include <string.h>	/* for str*()  */
#include <io.h>		/* for write() */

int	opterr = 1;	/* boolean flag, says "report error on stderr." */
int	optind = 1;	/* index to element of argv from which options are 
                        ** being parsed. */
int	optopt = 0;	/* option character */
char	*optarg;	/* ptr to option's parameter arg. */

#ifdef _WIN32
static void
do_opterr(const char *s, int c, char * const av[])
{
    if (opterr) {
	char buff[2];
	int fd = _fileno(stderr);

	buff[0] = (char)c; 
	buff[1] = '\n';
	(void)write(fd, av[0], strlen(av[0]));
	(void)write(fd, s, strlen(s));
	(void)write(fd, buff, 2);
    }
}
#define ERR(s, c) do_opterr(s, c, av)
#else
#define ERR(s, c) /* Win16 doesn't do stderr */
#endif

/*
**  Return options and their values from the command line.
*/
int
getopt(int ac, char * const av[], const char * opts)
{
    static int	i = 1;	/* offset of current option char in current arg. */
    char	*p;	/* opt char in opts that matched. */

    /* Move to next value from argv? */
    if (i == 1) {
	if (optind >= ac || av[optind][0] != '-' || av[optind][1] == '\0')
	    return EOF;
	if (strcmp(av[optind], "--") == 0) {
	    optind++;
	    return EOF;
	}
    }

    /* Get next option character. */
    if ((optopt = av[optind][i]) == ':' ||
        (p = strchr(opts,  optopt)) == NULL) {
	ERR(": illegal option -- ", optopt);
	if (av[optind][++i] == '\0') {
	    optind++;
	    i = 1;
	}
	return '?';
    }

    /* Snarf argument? */
    if (*++p == ':') {
	if (av[optind][i + 1] != '\0')
	    optarg = &av[optind++][i + 1];
	else {
	    if (++optind >= ac) {
		ERR(": option requires an argument -- ", optopt);
		i = 1;
		return '?';
	    }
	    optarg = av[optind++];
	}
	i = 1;
    } else {
	if (av[optind][++i] == '\0') {
	    i = 1;
	    optind++;
	}
	optarg = NULL;
    }

    return optopt;
}

#endif /* XP_PC */
