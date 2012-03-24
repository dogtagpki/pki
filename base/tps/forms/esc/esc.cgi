#! /usr/bin/perl -w
#
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#
########################################################################
#    
# Script: esc.cgi  
# Author: Kin Blas ()
# Date:   12/19/2003
#
# CGI.pm Docs:
#    
#    http://stein.cshl.org/WWW/software/CGI/
#    
########################################################################

use CGI;

$gQuery = new CGI;

$gQueryAction = "default";
$gQueryOverrideAction = "default";

@gCookieNames = ("ascScreenName",
                 "ascSubscriptionType",
                 "ascBindings");

$gQueryAction = $gQuery->param("action") if (defined $gQuery->param("action"));

$gQueryOverrideAction = $gQuery->param("override_action") 
				if (defined $gQuery->param("override_action"));

if ($gQueryOverrideAction ne "default") 
{
  $gQueryAction = $gQueryOverrideAction;
}

########################################################################
#
# If no action was provided, we default to showing our
# admin page!
#
#   http://www.foo.com/esc.cgi
#
########################################################################

if ($gQueryAction eq "default")
{
  GenerateAdminPage(); 
  exit 0;
}

########################################################################
#
# We aren't doing any admin functions, before proceeding
# on to user specific functions, make sure we have a screen name
# and that they are subscribed to a service.
#
########################################################################

#if (!HaveScreenName() || $gQueryAction eq "screennamepage")
#{
#  GenerateScreenNamePage($gQueryAction);
#  exit 0;
#}

LoadUserDatabase("default");

########################################################################
#
# Subscribe?
#
#   http://www.foo.com/esc.cgi?action=subscribe
#
########################################################################

#if ($gQueryAction eq "subscribe")
#{
#  SaveSubscription();
#  $nextAction = GetNextAction();
#  $redirectLocation = $gQuery->url(-path_info=>1)."?action=$nextAction&screenname=".GetScreenName();
#  print $gQuery->redirect(-uri=>$redirectLocation);
#  exit 0;
#}

#if (!IsSubscriber() || $gQueryAction eq "subscriptionpage")
#{
#  GenerateTOSPage($gQueryAction);
#  exit 0;
#}

########################################################################
#
# Show our cookie management page?
#
#   http://www.foo.com/esc.cgi?action=cookiepage
#
########################################################################

#if ($gQueryAction eq "cookiepage")
#{
#  GenerateCookiesPage(); 
#  exit 0;
#}

########################################################################
#
# Clear cookies?
#
#   http://www.foo.com/esc.cgi?action=clearAllCookies
#
########################################################################

#if ($gQueryAction eq "removeCookies")
#{
#  @expCookies = ();
#  foreach $cookie (@gCookieNames)
#  {
#    if (defined $gQuery->param($cookie))
#    {
#      $expCookies[$cookieCnt++] = CreateExpiredCookie($cookie);
#    }
#  }
#  $redirectLocation = $gQuery->url(-path_info=>1)."?action=cookiepage&screenname=".GetScreenName();
#  print $gQuery->redirect(-uri=>$redirectLocation,
#                          -cookie=>\@expCookies);
#  exit 0;
#}

########################################################################
#
# Bind?
#
#
########################################################################

if ($gQueryAction eq "bind")
{
  UpdateBindingsForBind();
  $nextAction = GetNextAction();

  $nextAction = "bindpage" if ($nextAction eq $gQueryAction);

  $redirectLocation = $gQuery->url(-path_info=>1)."?action=$nextAction&prevaction=bind&screenname=".GetScreenName()."&keytype=".GetKeyType()."&keyid=".GetKeyID()."&keylabel=".GetKeyLabelArg();
  print $gQuery->redirect(-uri=>$redirectLocation);
  exit 0;
}

########################################################################
#
# Unbind?
#
#
########################################################################

if ($gQueryAction eq "unbind")
{
  UpdateBindingsForUnbind();

  $nextAction = GetNextAction();

  $nextAction = "bindpage" if ($nextAction eq $gQueryAction);

  $redirectLocation = $gQuery->url(-path_info=>1)."?action=$nextAction&prevaction=unbind&screenname=".GetScreenName()."&keytype=".GetKeyType()."&keyid=".GetKeyID()."&keylabel=".GetKeyLabelArg();
  print $gQuery->redirect(-uri=>$redirectLocation);
  exit 0;
}

########################################################################
#
# Label?
#
#
########################################################################

if ($gQueryAction eq "label")
{
  UpdateBindingsForLabel();

  $nextAction = GetNextAction();

  $nextAction = "bindpage" if ($nextAction eq $gQueryAction);

  $redirectLocation = $gQuery->url(-path_info=>1)."?action=$nextAction&screenname=".GetScreenName();
  print $gQuery->redirect(-uri=>$redirectLocation);
  exit 0;
}

########################################################################
#
# ScreenName?
#
#
########################################################################

#if ($gQueryAction eq "screenname")
#{
#  $nextAction = GetNextAction();
#  $redirectLocation = $gQuery->url(-path_info=>1)."?action=$nextAction&screenname=".GetScreenName();
#  print $gQuery->redirect(-uri=>$redirectLocation);
#  exit 0;
#}

########################################################################
#
# Check if we are displaying the label page.
#
#
########################################################################

if ($gQueryAction eq "labelpage")
{
  my $nextAction = GetNextAction();
  $nextAction = "bindpage" if ($nextAction eq $gQueryAction);

  my $keyType = GetKeyType();
  my $keyId = GetKeyID();

  GenerateLabelPage($keyType, $keyId, $nextAction);
  exit 0;
}

########################################################################
#
# Show our enrollment page?
#
#   http://www.foo.com/esc.cgi?action=enrollmentpage
#
########################################################################

if ($gQueryAction eq "enrollmentpage")
{
  GenerateEnrollmentPage(); 
  exit 0;
}

if ($gQueryAction eq "advancepage")
{
  GenerateAdvancePage(); 
  exit 0;
}

if ($gQueryAction eq "tokenmanagerpage")
{
  GenerateTokenManagerPage(); 
  exit 0;
}

if($gQueryAction eq "authenticate")
{

   GenerateAuthenticationPage();
   exit 0;
}
 
if ($gQueryAction eq "autoenroll")
{
  GenerateAutoEnrollmentPage(); 
  exit 0;
}

########################################################################
#
# Show our ticket request page?
#
#
########################################################################

if ($gQueryAction eq "ticketreqpage")
{
  GenerateTicketRequestPage(); 
  exit 0;
}

########################################################################
#
# Show our load external url page?
#
#   http://www.foo.com/esc.cgi?action=loadurlpage
#
########################################################################


if ($gQueryAction eq "loadurl")
{
  $nextAction = GetNextAction();
  $redirectLocation = $gQuery->param('url');
  print $gQuery->redirect(-uri=>$redirectLocation);
  exit 0;
}

if ($gQueryAction eq "loadurlpage")
{
  GenerateLoadURLPage(); 
  exit 0;
}

########################################################################
#
# User is subscribed, check if we are displaying the
# settings page.
#
#
########################################################################

if ($gQueryAction eq "settingspage")
{
  GenerateSettingsPage();
  exit 0;
}

########################################################################
#
# Check if we are displaying the set label page.
#
#
########################################################################

if ($gQueryAction eq "setlabelpage")
{
  GenerateSetLabelPage();
  exit 0;
}

########################################################################
#
# Check if we are displaying the bind/unbind progress page!
#
#
########################################################################

if ($gQueryAction eq "bindprogresspage")
{
  GenerateBindProgressPage("bind");
  exit 0;
}

if ($gQueryAction eq "unbindprogresspage")
{
  GenerateBindProgressPage("unbind");
  exit 0;
}

########################################################################
#
# Check if we are displaying the bind/unbind success page!
#
#
########################################################################

if ($gQueryAction eq "bindsuccesspage")
{
  GenerateBindSuccessPage("bind");
  exit 0;
}

if ($gQueryAction eq "unbindsuccesspage")
{
  GenerateBindSuccessPage("unbind");
  exit 0;
}

########################################################################
#
# XXX: Lose this code!
# User is subscribed, check if we are displaying the
# binding page.
#
#
########################################################################

if ($gQueryAction eq "bindpage")
{
  GenerateBindingConfigPage();
  exit 0;
}

print "<html><body><H1> Unknown Query Action ";
print $qQueryAction;
print "</H1></body></html>";
exit 0;

########################################################################
#
#
########################################################################


sub ExitError
{
  my($str) = @_;
  print $gQuery->header(), $gQuery->start_html(), $str, $gQuery->end_html();
  exit 0;
}

sub GetScreenName
{
  my $sn = "";

  if (defined $gQuery->param("screenname"))
  {
    $sn = $gQuery->param("screenname");
  } else {
    $sn = "default";
  }

  return $sn;
}

sub GetKeyType
{
  my $keyType = 0;

  if (defined $gQuery->param("keytype"))
  {
    $keyType = $gQuery->param("keytype");
  }

  return $keyType;
}

sub GetKeyID
{
  my $keyID = "";

  if (defined $gQuery->param("keyid"))
  {
    $keyID = $gQuery->param("keyid");
  }

  return $keyID;
}

sub GetKeyLabelArg
{
  my $keyLabel = "";

  if (defined $gQuery->param("keylabel"))
  {
    $keyLabel = $gQuery->param("keylabel");
  }

  return $keyLabel;
}

sub HaveScreenName
{
  return 1 if (GetScreenName() ne "");
  return 0;
}

sub IsSubscriber
{
  my $subType = $gUserObj{'SUBSCRIPTION'};
  return 1 if ($subType eq "HouseKey" || $subType eq "NetKey");

  return 0;
}

sub GetNextAction
{
  my($nextActn) = "default";

  if (defined $gQuery->param('nextaction'))
  {
    $nextActn = $gQuery->param('nextaction');
  }
  elsif (defined $gQuery->param('action'))
  {
    $nextActn = $gQuery->param('action');
  }

  return $nextActn;
}

sub GenerateAdminPage()
{
  my ($l);

  ExitError("Failed to load Admin Page") if (!open(ADMIN_FILE, "< ./AdminEsc.html"));

  print $gQuery->header();

  while ($l = <ADMIN_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
    }
    print $l;
  }
  close(ADMIN_FILE);
}

sub GenerateCookiesPage()
{
  my ($nextPage) = @_;

  my ($l);

  ExitError("Failed to load TOS Page") if (!open(COOKIE_FILE, "< Cookies.html"));

  print $gQuery->header();

  while ($l = <COOKIE_FILE>)
  {
    if ($l =~ /SECURECOOL_COOKIE_LIST/)
    {
      my @cookies = $gQuery->cookie();
      if (@cookies < 1)
      {
        print "No ASC Cookies currently defined!<br>\n";
      }
      else
      {
        my $cookieName;
        foreach $cookieName (@cookies)
        {
          #
          # Display only ASC related cookies!
          #

          if ($cookieName =~ /^asc/)
          {
            print "<tr><td valign=\"center\" align=\"center\"><input type=\"checkbox\" name=\"$cookieName\"></td><td>$cookieName</td><td>", $gQuery->cookie($cookieName), "</td></tr>\n";
          }
        }
        print "<br>\n";
      }
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(COOKIE_FILE);
}

sub GenerateScreenNamePage
{
  my ($nextPage) = @_;

  my ($l);

  ExitError("Failed to load ScreenName Page") if (!open(SN_FILE, "< ScreenName.html"));

  print $gQuery->header();

  my $sn = GetScreenName();

  while ($l = <SN_FILE>)
  {
    if ($l =~ /SECURECOOL_NEXTACTION_INPUT_TAG/)
    {
      if ($nextPage)
      {
        print "<input type=\"hidden\" name=\"nextaction\" value=\"$nextPage\">\n";
        print "<input type=\"hidden\" name=\"screenname\" value=\"$sn\">\n";
      }

      if ($sn)
      {
        print "<script>document.getElementById('screenname').value = \"$sn\"</script>\n";
      }
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(SN_FILE);
}

sub GenerateTOSPage
{
  my ($nextPage) = @_;

  my ($l);

  ExitError("Failed to load TOS Page") if (!open(TOS_FILE, "< Subscribe.html"));

  print $gQuery->header();

  while ($l = <TOS_FILE>)
  {
    if ($l =~ /SECURECOOL_NEXTACTION_INPUT_TAG/)
    {
      if ($nextPage)
      {
        print "<input type=\"hidden\" name=\"nextaction\" value=\"$nextPage\">\n";
        print "<input type=\"hidden\" name=\"screenname\" value=\"". GetScreenName() ."\">\n";
      }
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(TOS_FILE);
}

sub GenerateSettingsPage
{
  my ($l);

  ExitError("Failed to load settings page!") if (!open(SETTINGS_FILE, "< SettingsEsc.html"));

  print $gQuery->header();

  while ($l = <SETTINGS_FILE>)
  {
    if ($l =~ /SECURECOOL_BINDINGS_ARRAY/)
    {
      my(@curBindings) = GetBindings();
      my $arrSize = scalar(@curBindings);
      my($i);

      for ($i = 0; $i < $arrSize; $i++)
      {
        my($keyType, $keyId, $keyLabel) = split(/&/, $curBindings[$i]);
        print "  [ $keyType, \"$keyId\", \"$keyLabel\" ]";
        print "," if ($arrSize > 1 && $i != $arrSize - 1);
        print "\n";
      }
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(SETTINGS_FILE);
}

sub GenerateSetLabelPage
{
  my ($l);

  ExitError("Failed to open label page!") if (!open(LABEL_PAGE, "< Label.html"));

  my $sn = GetScreenName();
  ExitError("Failed to get a valid screen name!") if (! $sn);

  my $keyType = GetKeyType();
  my $keyID = GetKeyID();
  ExitError("Failed to get a valid keyID!") if (! $keyID);

  $defLabel = $keyID;
  $defLabel =~ s/^[0-9a-fA-F]{12}//;
  $defLabel = "$sn-$defLabel";

  print $gQuery->header();

  while ($l = <LABEL_PAGE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYTYPE *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYTYPE *-->/$keyType/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYID *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYID *-->/$keyID/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYLABEL *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYLABEL *-->/$defLabel/g;
    }
    print $l;
  }
  close(LABEL_FILE);
}

sub GenerateBindProgressPage
{
  my ($action) = @_;
  my ($l);

  ExitError("Failed to open progress page!") if (!open(PROG_PAGE, "< Progress.html"));

  my $sn = GetScreenName();
  ExitError("Failed to get a valid screen name!") if (! $sn);

  my $keyType = GetKeyType();
  my $keyID = GetKeyID();
  ExitError("Failed to get a valid keyID!") if (! $keyID);

  my $keyLabel = "";

  if ($action eq "bind")
  {
    $keyLabel = GetKeyLabelArg();
    ExitError("Failed to get a valid keyLabel!") if (! $keyLabel);
  }

  print $gQuery->header();

  while ($l = <PROG_PAGE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYTYPE *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYTYPE *-->/$keyType/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYID *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYID *-->/$keyID/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYLABEL *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYLABEL *-->/$keyLabel/g;
    }
    if ($l =~ /<!-- *SECURECOOL_ACTION *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_ACTION *-->/$action/g;
    }
    if ($l =~ /<!-- *SECURECOOL_CHALLENGEDATA *-->/)
    {
      $challengeData = "";
      $challengeData = "QVNDIHJvY2tzIHRoZSBwYXJ0eSE=" if ($action eq "bind");

      $l =~ s/<!-- *SECURECOOL_CHALLENGEDATA *-->/$challengeData/g;
    }
    print $l;
  }
  close(PROG_PAGE);
}

sub GenerateBindSuccessPage
{
  my ($action) = @_;
  my ($l);

  ExitError("Failed to open progress page!") if (!open(SUCCESS_PAGE, "< BindSuccess.html"));

  my $sn = GetScreenName();
  ExitError("Failed to get a valid screen name!") if (! $sn);

  my $keyType = GetKeyType();
  my $keyID = GetKeyID();
  ExitError("Failed to get a valid keyID!") if (! $keyID);

  my $keyLabel = "";
  
  if ($action eq "bind")
  {
    $keyLabel = GetKeyLabelArg();
    ExitError("Failed to get a valid keyLabel!") if (! $keyLabel);
  }

  print $gQuery->header();

  while ($l = <SUCCESS_PAGE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYTYPE *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYTYPE *-->/$keyType/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYID *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYID *-->/$keyID/g;
    }
    if ($l =~ /<!-- *SECURECOOL_KEYLABEL *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_KEYLABEL *-->/$keyLabel/g;
    }
    if ($l =~ /<!-- *SECURECOOL_ACTION *-->/)
    {
      $l =~ s/<!-- *SECURECOOL_ACTION *-->/$action/g;
    }
    print $l;
  }
  close(SUCCESS_PAGE);
}

sub GenerateBindingConfigPage
{
  my ($l);

  ExitError("Failed to load binding page!") if (!open(BINDING_FILE, "< Bindings.html"));

  print $gQuery->header();

  while ($l = <BINDING_FILE>)
  {
    if ($l =~ /SECURECOOL_BINDINGS_ARRAY/)
    {
      my(@curBindings) = GetBindings();
      my $arrSize = scalar(@curBindings);
      my($i);

      for ($i = 0; $i < $arrSize; $i++)
      {
        my($keyType, $keyId, $keyLabel) = split(/&/, $curBindings[$i]);
        print "  [ $keyType, \"$keyId\", \"$keyLabel\" ]";
        print "," if ($arrSize > 1 && $i != $arrSize - 1);
        print "\n";
      }
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(BINDING_FILE);
}

sub GetKeyLabel
{
  my($keyType, $keyId) = @_;

  my(@curBindings) = GetBindings();
  my($numBindings) = scalar(@curBindings);

  while($numBindings > 0)
  {
    --$numBindings;
    if ($curBindings[$numBindings] =~ /^$keyType&$keyId&/)
    {
      my($ktype, $id, $lbl) = split(/&/, $curBindings[$numBindings]);
      return $lbl;
    }
  }

  return "";
}

sub GenerateLabelPage
{
  my($keyType, $keyId, $nextAction) = @_;
  my($keyLabel) = GetKeyLabel($keyType, $keyId);

  return if ($keyLabel eq "");

  my ($l);

  ExitError("Failed to load label page!") if (!open(EDIT_LABEL_FILE, "< EditLabel.html"));

  print $gQuery->header();

  while ($l = <EDIT_LABEL_FILE>)
  {
    if ($l =~ /SECURECOOL_NEXTACTION_INPUT_TAG/)
    {
      print "<input type=\"hidden\" name=\"nextaction\" value=\"$nextAction\">\n";
      print "<input type=\"hidden\" name=\"keytype\" value=\"$keyType\">\n";
      print "<input type=\"hidden\" name=\"keyid\" value=\"$keyId\">\n";
      print "<input type=\"hidden\" name=\"keylabel\" value=\"$keyLabel\">\n";
      print "<input type=\"hidden\" name=\"screenname\" value=\"".GetScreenName()."\">\n";
    }
    elsif ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }
  close(EDIT_LABEL_FILE);
}

sub GenerateAutoEnrollmentPage
{
  my ($l);

  ExitError("Failed to load enrollment page!") if (!open(ENROLL_FILE, "< EnrollPopup.html"));

  print $gQuery->header();

  while ($l = <ENROLL_FILE>)
  {
    print $l;
  }

  close(ENROLL_FILE);
}
sub GenerateAuthenticationPage
{
  my ($l); 
  ExitError("Failed to load enrollment page!") if (!open(AUTH_FILE, "< GenericAuth.html"));

  print $gQuery->header();

  while ($l = <AUTH_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(AUTH_FILE);
}

sub GenerateEnrollmentPage
{
  my ($l);

  ExitError("Failed to load enrollment page!") if (!open(ENROLL_FILE, "< EnrollPopup.html"));

  print $gQuery->header();

  while ($l = <ENROLL_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(ENROLL_FILE);
}

sub GenerateAdvancePage
{
  my ($l);

  ExitError("Failed to load enrollment page!") if (!open(ENROLL_FILE, "< AdvancePopup.html"));

  print $gQuery->header();

  while ($l = <ENROLL_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(ENROLL_FILE);
}

sub GenerateTokenManagerPage
{
  my ($l);

  ExitError("Failed to load enrollment page!") if (!open(ENROLL_FILE, "< TokenManager.html"));

  print $gQuery->header();

  while ($l = <ENROLL_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(ENROLL_FILE);
}

sub GenerateTicketRequestPage
{
  my ($l);

  ExitError("Failed to load ticket request page!") if (!open(TICKETREQ_FILE, "< Ticket.html"));

  print $gQuery->header();

  while ($l = <TICKETREQ_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(TICKETREQ_FILE);
}

sub GenerateLoadURLPage
{
  my ($l);

  ExitError("Failed to load url request page!") if (!open(LOADURL_FILE, "< LoadURL.html"));

  print $gQuery->header();

  while ($l = <LOADURL_FILE>)
  {
    if ($l =~ /<!-- *SECURECOOL_SCREENNAME *-->/)
    {
      my $sn = GetScreenName();
      $l =~ s/<!-- *SECURECOOL_SCREENNAME *-->/$sn/g;
      print $l;
    }
    else
    {
      print $l;
    }
  }

  close(LOADURL_FILE);
}

sub CreateExpiredCookie
{
  my($cookieName) = @_;
  my $cookie = $gQuery->cookie(-name=>$cookieName,
                               -value=>'',
                               -expires=>'-2d',
                               -path=>$gQuery->url(-absolute=>1),
                               -domain=>$gQuery->server_name());
  return $cookie;

}

sub SaveSubscription
{
  
  $gUserObj{'SUBSCRIPTION'} = $gQuery->param("subscriptiontype");
  SaveUserDatabase(GetScreenName());
}

sub GetBindings
{
  my $bindings = $gUserObj{'BINDINGS'};
  return @$bindings;
}

sub BindingsArrayToString
{
  my(@bindings) = @_;
  my $i;
  my $str = "";

  for ($i = 0; $i < @bindings; $i++)
  {
    if ($bindings[$i] ne "")
    {
      $str .= "&" if ($str ne "");
      $str .= ASCUrlEncode($bindings[$i]);
    }
  }

  return $str;
}

sub AddItemToBindings
{
  my($keyType, $keyId, $keyLabel) = @_;

  my(@curBindings) = GetBindings();
  my($pos) = scalar(@curBindings);

  # First check to see if the key already  exists in
  # the  cookie! If it does, we'll just overwrite it.

  my($i) = $pos;
  while($i > 0)
  {
    --$i;
    if ($curBindings[$i] =~ /^$keyType&$keyId&/)
    {
      $pos = $i;
      last;
    }
  }

  $curBindings[$pos] = "$keyType&$keyId&$keyLabel";

  $gUserObj{'BINDINGS'} = \@curBindings;
  #SaveUserDatabase(GetScreenName());
}

sub RemoveItemFromBindings
{
  my($keyType, $keyId) = @_;

  my(@curBindings) = GetBindings();
  my($numBindings) = scalar(@curBindings);
  my @newBindings;

  while($numBindings > 0)
  {
    --$numBindings;
    next if ($curBindings[$numBindings] =~ /^$keyType&$keyId&/);
    push @newBindings, $curBindings[$numBindings];
  }

  $gUserObj{'BINDINGS'} = \@newBindings;
  #SaveUserDatabase(GetScreenName());
}

sub UpdateBindingsForBind
{
  return if (! defined $gQuery->param("keytype"));
  my($keyType) = $gQuery->param("keytype");

  return if (! defined $gQuery->param("keyid"));
  my($keyId) = $gQuery->param("keyid");

  return if (! defined $gQuery->param("keylabel"));
  my($keyLabel) = $gQuery->param("keylabel");

  return AddItemToBindings($keyType, $keyId, $keyLabel);
}

sub UpdateBindingsForUnbind
{
  return if (! defined $gQuery->param("keytype"));
  my($keyType) = $gQuery->param("keytype");

  return if (! defined $gQuery->param("keyid"));
  my($keyId) = $gQuery->param("keyid");

  return RemoveItemFromBindings($keyType, $keyId,);
}

sub UpdateBindingsForLabel
{
  return UpdateBindingsForBind();
}

sub ASCUrlDecode
{
  my($qstr) = @_;
  $qstr =~ s/\+/ /g;
  $qstr =~ s/%([0-9A-F]{2})/pack("C", hex($1))/eig;
  return $qstr;
}

sub ASCUrlEncode
{
  my($qstr) = @_;
  $qstr =~ s/([^a-zA-Z0-9_ ])/sprintf("%%%.2X", unpack("C", $1))/eig;
  $qstr =~ s/ /+/g;
  return $qstr;
}

sub LoadUserDatabase
{
  my($sn) = @_; 

  $gUserObj{'SUBSCRIPTION'}  = "";

  $gUserObj{'BINDINGS'} = "";
  return;

}

sub SaveUserDatabase
{
  my($sn) = @_;
  my($snfile) = "UserDatabase/$sn";

  return;

}
