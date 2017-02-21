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
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

$(function() {

// if secure connection
if (location.protocol == "https:" && !sessionStorage.bannerLock) {

    sessionStorage.bannerLock = true;

    // get server info (including banner)
    PKI.getInfo({
        success: function(data, textStatus, jqXHR) {

            // if banner not available, skip
            if (!data.Banner) {
                delete sessionStorage.bannerLock;
                return;
            }

            // display the banner and ask for confirmation
            var message = $.trim(data.Banner) + "\n\nDo you want to proceed?";

            // if banner accepted
            if (confirm(message)) {

                // perform login
                PKI.login({
                    success: function(data, textStatus, jqXHR) {

                        // done
                        delete sessionStorage.bannerLock;
                    },
                    error: function(jqXHR, textStatus, errorThrown) {

                        // unable to login, display error
                        alert(textStatus);

                        delete sessionStorage.bannerLock;
                    }
                });

            } else {
                delete sessionStorage.bannerLock;

                // redirect to PKI UI welcome page
                window.location = '/pki';
            }
        },
        error: function(jqXHR, textStatus, errorThrown) {

            // unable to get server info, display error
            alert(textStatus);

            delete sessionStorage.bannerLock;
        }
    });
}
});
