//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

function getDirectory(options) {
    $.get({
        url: "directory",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function getLoginInfo(options) {
    $.get({
        url: "login",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function updateHomePage() {
    getDirectory({
        success: function(data, textStatus, jqXHR) {
            $("#metadata-termsOfService").text(data.meta.termsOfService);
            $("#metadata-termsOfService").attr("href", data.meta.termsOfService);
            $("#metadata-website").text(data.meta.website);
            $("#metadata-website").attr("href", data.meta.website);
            $("#metadata-caaIdentities").text(data.meta.caaIdentities.join(", "));
            $("#metadata-externalAccountRequired").text(data.meta.externalAccountRequired);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert('ERROR: ' + errorThrown);
        }
    });
}

function updateBaseURL() {

    // replace BASE_URL with actual base URL
    var i = window.location.href.lastIndexOf('/');
    var base_url = window.location.href.substring(0, i);

    $("pre").each(function() {
        var content = this.innerText;
        this.innerText = content.replace("BASE_URL", base_url);
    });
}

function setUserProfile(data) {
    $("#profile-fullName").text(data.FullName);
}

function clearUserProfile() {
    $("#profile-fullName").text("");
}

function updateLoginInfo() {
    getLoginInfo({
        success: function(data, textStatus, jqXHR) {
            if (jqXHR.status == 200) {
                setUserProfile(data);
            } else {
                clearUserProfile();
            }

        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert('ERROR: ' + errorThrown);
        }
    });
}
