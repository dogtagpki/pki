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

function login(options) {
    $.post({
        url: "login",
        dataType: "json"
    }).done(function(data, textStatus, jqXHR) {
        if (options.success) options.success.call(self, data, textStatus, jqXHR);
    }).fail(function(jqXHR, textStatus, errorThrown) {
        if (options.error) options.error.call(self, jqXHR, textStatus, errorThrown);
    });
}

function logout(options) {
    $.post({
        url: "logout",
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
    $(".login-menu").hide();
    $(".logout-menu").show();
}

function clearUserProfile() {
    $("#profile-fullName").text("");
    $(".login-menu").show();
    $(".logout-menu").hide();
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

function showProfileMenu() {

    var button = $("#profile-menu");
    button.attr("aria-expanded", true);

    var parent = button.parent();
    parent.addClass("pf-m-expanded");

    var menu = $("ul[aria-labelledby='profile-menu']");
    menu.attr("hidden", false);
}

function hideProfileMenu() {

    var button = $("#profile-menu");
    button.attr("aria-expanded", false);

    var parent = button.parent();
    parent.removeClass("pf-m-expanded");

    var menu = $("ul[aria-labelledby='profile-menu']");
    menu.attr("hidden", true);
}

function activateProfileMenu() {

    $("#profile-menu").on({
        click: function() {
            var collapsed = $(this).attr("aria-expanded") == "false";
            if (collapsed) {
                showProfileMenu();
            } else {
                hideProfileMenu();
            }
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });

    $(".login-menu a").on({
        click: function() {
            hideProfileMenu();
            login({
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
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });

    $(".logout-menu a").on({
        click: function() {
            hideProfileMenu();
            logout({
                success: function(data, textStatus, jqXHR) {
                    clearUserProfile();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert('ERROR: ' + errorThrown);
                }
            });
        },
        keydown: function (e) {
            if (e.which === 27) {
                hideProfileMenu();
                e.preventDefault();
            }
        }
    });
}

function loadPage(url, callback) {
    $(".pf-c-content").load(url, callback);
}

function activateSidebarMenu() {

    $(".home-menu a").on({
        click: function() {
            $("#sidebar a").removeClass("pf-m-current");
            $(this).addClass("pf-m-current");
            loadPage("home.jsp", function() {
                updateHomePage();
            });
        }
    });

    $(".services-menu a").on({
        click: function() {
            $("#sidebar a").removeClass("pf-m-current");
            $(this).addClass("pf-m-current");
            loadPage("services.jsp", function() {
                updateBaseURL();
            });
        }
    });
}
