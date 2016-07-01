#!/bin/sh
#Include below files
. /opt/rhqa_pki/env.sh
##################################################################
#enable_netscape_extension add netscape extensions to a profile xml
#it takes arguments of form:
#enable_netscape_ext location_of_xml_file netscape_ext1 netscape_ext2 ....
################################################################
enable_netscape_ext()
{
profile_xml="$1"
arg_array=($@)
arg_array=("${arg_array[@]:1}")
current_highest_valueid=$(cat $profile_xml  | grep "value id" | awk -F "\"" '{print $2}' | sort -n | tail -n 1)
new_value_id=$(expr $current_highest_valueid + 1)

rlLog "Define a new subnode value containing def and desciption as it's elements"
rlRun "xmlstarlet ed -L -s /Profile/PolicySets/PolicySet --type elem -n 'value id=\"$new_value_id\"' -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]\" --type elem -n \"def\" -v \"\" $profile_xml"

rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type attr -n \"id\" -v \"Netscape Certificate Type Extension Default\" $profile_xml"


rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type attr -n \"classId\" -v \"nsCertTypeExtDefaultImpl\" $profile_xml"

rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"description\" -v \"This default populates a Netscape Certificate Type Extension\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertCritical"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute\" --type attr -n \"name\" -v \"nsCertCritical\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertCritical')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertCritical')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertCritical')]/Descriptor\" --type elem -n \"Description\" -v \"Criticality\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertCritical')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"
rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertSSLClient"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')]\" --type attr -n \"name\" -v \"nsCertSSLClient\" $profile_xml"

rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLClient')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLClient')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLClient')]/Descriptor\" --type elem -n \"Description\" -v \"SSL Client\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLClient')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertSSLServer"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')]\" --type attr -n \"name\" -v \"nsCertSSLServer\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLServer')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLServer')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLServer')]/Descriptor\" --type elem -n \"Description\" -v \"SSL Server\" $profile_xml"

rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLServer')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertEmail"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')]\" --type attr -n \"name\" -v \"nsCertEmail\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmail')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmail')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmail')]/Descriptor\" --type elem -n \"Description\" -v \"Email\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmail')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertObjectSigning"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')]\" --type attr -n \"name\" -v \"nsCertObjectSigning\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigning')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigning')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigning')]/Descriptor\" --type elem -n \"Description\" -v \"Object Signing\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigning')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertSSLCA"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')]\" --type attr -n \"name\" -v \"nsCertSSLCA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLCA')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLCA')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLCA')]/Descriptor\" --type elem -n \"Description\" -v \"SSL CA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertSSLCA')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertEmailCA"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')][not(@name='nsCertSSLCA')]\" --type attr -n \"name\" -v \"nsCertEmailCA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmailCA')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmailCA')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmailCA')]/Descriptor\" --type elem -n \"Description\" -v \"Email CA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertEmailCA')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode with PolicyAttribute under value containing Netscape Extension nsCertObjectSigningCA"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"policyAttribute\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')][not(@name='nsCertSSLCA')][not(@name='nsCertEmailCA')]\" --type attr -n \"name\" -v \"nsCertObjectSigningCA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigningCA')]\" --type elem -n \"Descriptor\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigningCA')]/Descriptor\" --type elem -n \"Syntax\" -v \"boolean\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigningCA')]/Descriptor\" --type elem -n \"Description\" -v \"Object Signing CA\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/policyAttribute[(@name='nsCertObjectSigningCA')]/Descriptor\" --type elem -n \"DefaultValue\" -v \"false\" $profile_xml"

rlLog "Define a new subnode params under value Specifying what Netscape Extensions are enabled"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params\" --type attr -n \"name\" -v \"nsCertCritical\" $profile_xml"
	if [ "nsCertCritical" == "${arg_array[0]}" ] || \
	[ "nsCertCritical" == "${arg_array[1]}" ] || \
	[ "nsCertCritical" == "${arg_array[2]}" ] || \
	[ "nsCertCritical" == "${arg_array[3]}" ] || \
	[ "nsCertCritical" == "${arg_array[4]}" ] || \
	[ "nsCertCritical" == "${arg_array[5]}" ] || \
	[ "nsCertCritical" == "${arg_array[6]}" ]; then 
		rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertCritical')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
	else 
		rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertCritical')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
	fi

rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')]\" --type attr -n \"name\" -v \"nsCertSSLClient\" $profile_xml"
        if [ "nsCertSSLClient" == "${arg_array[0]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[1]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[2]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[3]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[4]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[5]}" ] || \
        [ "nsCertSSLClient" == "${arg_array[6]}" ]; then
               rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLClient')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLClient')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')]\" --type attr -n \"name\" -v \"nsCertSSLServer\" $profile_xml"
        if [ "nsCertSSLServer" == "${arg_array[0]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[1]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[2]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[3]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[4]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[5]}" ] || \
        [ "nsCertSSLServer" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLServer')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLServer')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')]\" --type attr -n \"name\" -v \"nsCertEmail\" $profile_xml"
 if [ "nsCertEmail" == "${arg_array[0]}" ] || \
        [ "nsCertEmail" == "${arg_array[1]}" ] || \
        [ "nsCertEmail" == "${arg_array[2]}" ] || \
        [ "nsCertEmail" == "${arg_array[3]}" ] || \
        [ "nsCertEmail" == "${arg_array[4]}" ] || \
        [ "nsCertEmail" == "${arg_array[5]}" ] || \
        [ "nsCertEmail" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertEmail')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertEmail')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')]\" --type attr -n \"name\" -v \"nsCertObjectSigning\" $profile_xml"
 if [ "nsCertObjectSigning" == "${arg_array[0]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[1]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[2]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[3]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[4]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[5]}" ] || \
        [ "nsCertObjectSigning" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertObjectSigning')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertObjectSigning')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')]\" --type attr -n \"name\" -v \"nsCertSSLCA\" $profile_xml"
 if [ "nsCertSSLCA" == "${arg_array[0]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[1]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[2]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[3]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[4]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[5]}" ] || \
        [ "nsCertSSLCA" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLCA')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertSSLCA')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')][not(@name='nsCertSSLCA')]\" --type attr -n \"name\" -v \"nsCertEmailCA\" $profile_xml"
 if [ "nsCertEmailCA" == "${arg_array[0]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[1]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[2]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[3]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[4]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[5]}" ] || \
        [ "nsCertEmailCA" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertEmailCA')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertEmailCA')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def\" --type elem -n \"params\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[not(@name='nsCertCritical')][not(@name='nsCertSSLClient')][not(@name='nsCertSSLServer')][not(@name='nsCertEmail')][not(@name='nsCertObjectSigning')][not(@name='nsCertSSLCA')][not(@name='nsCertEmailCA')]\" --type attr -n \"name\" -v \"nsCertObjectSigningCA\" $profile_xml"
 if [ "nsCertObjectSigningCA" == "${arg_array[0]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[1]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[2]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[3]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[4]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[5]}" ] || \
        [ "nsCertObjectSigningCA" == "${arg_array[6]}" ]; then
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertObjectSigningCA')]\" --type elem -n \"value\" -v \"true\" $profile_xml"
        else
                rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/def/params[(@name='nsCertObjectSigningCA')]\" --type elem -n \"value\" -v \"false\" $profile_xml"
        fi
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]\" --type elem  -n \"constraint\" -v \"\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/constraint\" --type attr -n \"id\" -v \"No Constraint\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/constraint[(@id='No Constraint')]\" --type elem -n \"description\" -v \"No Constraint\" $profile_xml"
rlRun "xmlstarlet ed -L -s \"/Profile/PolicySets/PolicySet/value[(@id=\"$new_value_id\")]/constraint[(@id='No Constraint')]\" --type elem -n \"classId\" -v \"noConstraintImpl\" $profile_xml"
return 0;
}
