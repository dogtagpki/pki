#!/bin/sh
########################################################################
#  RHCS SERVER CONFIG SHARED LIBRARY
#######################################################################
# Includes:
#       enable_big_int <startingRange Nunber> <Range> 
#
######################################################################
. /opt/rhqa_pki/env.sh

enable_big_int()
{
	StartValue=$(expr $1)	
	Range=$(expr $2)
	PKIDAEMON_STATUS="/tmp/bigInt-pkidaemon-status"
	CURRENT_CONF_FILE=$CA_SERVER_ROOT/conf/CS.cfg
	BACKUP_CONF_FILE=$CA_SERVER_ROOT/conf/CS.cfg.backupFile

	# Stop the pki-tomcat service 
	# To-Do: To be modified in case separate Tomcat Services 
	rlRun "/usr/bin/systemctl stop pki-tomcatd@pki-tomcat.service" 0 "Stop pki-tomcat service"

	# Verify pki-tomcat service is stop
	rlRun "/usr/bin/pkidaemon status tomcat pki-tomcat 1> $PKIDAEMON_STATUS" 3 "Verify pki-tomcat is stopped"
	rlAssertGrep "Status for pki-tomcat: pki-tomcat is stopped" "$PKIDAEMON_STATUS"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "pki-tomcat instance could not be stopped"
        	return 1
	fi
	#Take the backup of current configuration file 
	rlRun "/usr/bin/cp $CURRENT_CONF_FILE -f $BACKUP_CONF_FILE" 0 "Backup current CS.cfg"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not take backup of CS.cfg"
		return 1
	fi
	#Get current values
	OldReqStart=$(cat $CURRENT_CONF_FILE | grep dbs.beginRequestNumber)
	OldReqEnd=$(cat $CURRENT_CONF_FILE | grep dbs.endRequestNumber)
	OldReqInc=$(cat $CURRENT_CONF_FILE | grep dbs.requestIncrement)
	OldReqMark=$(cat $CURRENT_CONF_FILE | grep dbs.requestLowWaterMark)
	OldSerialStart=$(cat $CURRENT_CONF_FILE | grep dbs.beginSerialNumber)
	OldSerialEnd=$(cat $CURRENT_CONF_FILE | grep dbs.endSerialNumber)
	OldSerialInc=$(cat $CURRENT_CONF_FILE | grep dbs.serialIncrement)
	OldSerialMark=$(cat $CURRENT_CONF_FILE | grep dbs.serialLowWaterMark)

	OldReqStartValue=$(echo $OldReqStart | cut -d= -f2)
	OldReqEndValue=$(echo $OldReqEnd | cut -d= -f2)
	OldReqIncValue=$(echo $OldReqInc | cut -d= -f2)
	OldReqMarkValue=$(echo $OldReqMark | cut -d= -f2)
	OldSerialStartValue=$(echo $OldSerialStart | cut -d= -f2)
	OldSerialEndValue=$(echo $OldSerialEnd | cut -d= -f2)
	OldSerialIncValue=$(echo $OldSerialInc | cut -d= -f2)
	OldSerialMarkValue=$(echo $OldSerialMark | cut -d= -f2)

	# Set New Values 
	NewStart=$StartValue
	NewEnd=$(expr $StartValue + $Range - 1)
	NewInc=$Range
	NewMark=$(expr $Range \* 20 / 100)
	UpdatedReqStart=dbs.beginRequestNumber=$NewStart
	UpdatedReqEnd=dbs.endRequestNumber=$NewEnd
	UpdatedReqInc=dbs.requestIncrement=$NewInc
	UpdatedReqMark=dbs.requestLowWaterMark=$NewMark
	UpdatedSerialStart=dbs.beginSerialNumber=$NewStart
	UpdatedSerialEnd=dbs.endSerialNumber=$NewEnd
	UpdatedSerialInc=dbs.serialIncrement=$NewInc
	UpdatedSerialMark=dbs.serialLowWaterMark=$NewMark

# Replace configuration with New Range Numbers
	rlRun "sed -i s/"$OldReqStart"/"$UpdatedReqStart"/ $CURRENT_CONF_FILE" 0
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.beginRequestNumber"
	        return 1
	fi
	rlRun "sed -i s/"$OldReqEnd"/"$UpdatedReqEnd"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.endRequestNumber"
	        return 1
	fi
	rlRun "sed -i s/"$OldReqInc"/"$UpdatedReqInc"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.requestIncrement"
        	return 1
	fi
	rlRun "sed -i s/"$OldReqMark"/"$UpdatedReqMark"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.requestLowWaterMark"
        	return 1
	fi
	rlRun "sed -i s/"$OldSerialStart"/"$UpdatedSerialStart"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.beginSerialNumber"
        	return 1
	fi
	rlRun "sed -i s/"$OldSerialEnd"/"$UpdatedSerialEnd"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.endSerialNumber"
	        return 1
	fi
	rlRun "sed -i s/"$OldSerialInc"/"$UpdatedSerialInc"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.serialIncrement"
        	return 1
	fi
	rlRun "sed -i s/"$OldSerialMark"/"$UpdatedSerialMark"/ $CURRENT_CONF_FILE"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not modify value of dbs.serialLowWaterMark"
        	return 1
	fi

	#Start pki-tomcat service
	rlRun "/usr/bin/systemctl start pki-tomcatd@pki-tomcat.service"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "Could not start pki-tomcat service"
	        return 1
	fi
	#Verify pki-tomcat service 
	rlRun "/usr/bin/pkidaemon status tomcat pki-tomcat 1> $PKIDAEMON_STATUS"
	# Verify checks 
	rlAssertGrep "Status for pki-tomcat: pki-tomcat is running" "$PKIDAEMON_STATUS"

	# Verify if all the subsystems have started.
	rlAssertGrep "PKI Subsystem Type:  Root CA (Security Domain)" "$PKIDAEMON_STATUS" 
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "CA subsystem failed to start"
        	return 1
	fi
	rlAssertGrep "PKI Subsystem Type:  DRM" "$PKIDAEMON_STATUS" 
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "KRA Subsystem failed to start"
	        return 1
	fi
	rlAssertGrep "PKI Subsystem Type:  OCSP" "$PKIDAEMON_STATUS"
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "OCSP Subsystem failed to start"
	        return 1
	fi
	rlAssertGrep "PKI Subsystem Type:  TKS" "$PKIDAEMON_STATUS" 
	RETVAL=$?
	if [ $RETVAL != 0 ]; then
		rlLog "TKS Subsystem failed to start"
	        return 1
	fi
	return 0
}
