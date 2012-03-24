// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

//
// initialize netkey globals
var netkey;

var keyUITable = new Array();
var keyTypeTable = new Array();
var curChildWindow = null;

var gWindow = null;

const ErrorText = "For additional assistance contact your Technical Support";


function getUIForKey(aKeyID)
{
    return keyUITable[aKeyID];

}

function getTypeForKey(aKeyID)
{
    return keyTypeTable[aKeyID];
}


//
// Notify callback for GECKO
//
function jsNotify()  {}

jsNotify.prototype = {

  rhNotifyKeyStateChange: function(aKeyType,aKeyID,aKeyState,aData,strData)
  {
    OnCOOLKeyStateChange(aKeyType, aKeyID, aKeyState, aData,strData);
  },

  QueryInterface: function(iid)
  {
    <!--  alert("iid: " + iid); -->
     if(!iid.equals(Components.interfaces.rhIKeyNotify) &&
         !iid.equals(Components.interfaces.nsISupports))
      {
          MyAlert("Can't find jsNotify interface");
          throw Components.results.NS_ERROR_NO_INTERFACE;
      }
      return this;
  }
};

//
// Attach to the object.
//
  // GECKO ONLY initialization
  try {
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    netkey = Components.classes["@redhat.com/rhCoolKey"].getService();
    netkey = netkey.QueryInterface(Components.interfaces.rhICoolKey);
    gNotify = new jsNotify;
    netkey.rhCoolKeySetNotifyCallback(gNotify);
  } catch(e) {
     MyAlert("Can't get UniversalXPConnect: " + e);
  }

//
// unregister our notify event
//
function cleanup()
{

    try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
      netkey.rhCoolKeyUnSetNotifyCallback(gNotify);
    } catch(e) {
     MyAlert("Can't get UniversalXPConnect: " + e);
    }
}

var gScreenName = "";
var gKeyEnrollmentType = "userKey";

var gCurrentSelectedRow = null;


var gCurKeyType = null;
var gCurKeyID = null;

////////////////////////////////////////////////////////////////
//
// Utility functions specific to this page.
//
////////////////////////////////////////////////////////////////


// List of Error Messages to be printed out

var Status_Messages = new Array(
      
    "Operation Completed Successfully.",
    "Smartcard Server error.",
    "Problem communicating with the smartcard.",
    "Problem communicating with the smartcard.",
    "Problem resetting smartcard's pin.",
    "Internal Smartcard Server error.",
    "Internal Smartcard Server error.",
    "Smartcard enrollment error.",
    "Can not communicate with the smartcard.",
    "Internal Smartcard Server error.",
    "Problem communicating with the Certificattion Authority.",
    "Internal Smartcard Server error.",
    "Error resetting the smartcard's password.",
    "Internal Smartcard Server error.",
    "Smartcard Server authentication failure.",
    "Internal Smartcard Server error.",
    "Your Smartcard is listed as disabled.",
    "Problem communicating with the smartcard.",
    "Internal Smartcard Server error.",
    "Cannot upgrade smartcard software.",
    "Internal Smartcard Server error.",
    "Problem communicating with the smartcard.",
    "Invalid smartcard type.",
    "Invalid smartcard type.",
    "Cannot publish smartcard information.",
    "Cannot communicate with smartcard database.",
    "Smartcard is disabled.",
    "Cannot reset password value for the smartcard.",
    "Connection to Smartcard Server lost.",
    "Cannot create entry for smartcard in smartcard database.",
    "Smartcard found to be in an inconsistent state.",
    "Invalid reason for lost smartcard submitted.",
    "Smartcard found to be unusable due to compromise.",
    "No such inactive smartcard found.",
    "Cannot process more than one active smartcard.",
    "Internal Smartcard Server error.",
    "Smartcard key recovery has been processed.",
    "Smartcard key recovery failed.",
    "Cannot process this smartcard, which has been reported lost.",
    "Smartcard key archival error.",
    "Problem connecting to the Smartcard TKS Server.",
    "Failed to update smartcard database.",
    "Internal certificate revocation error discovered.",
    "User does not own this smartcard.", 
    "Smart Card Manager has been misconfigured.",
    "Smart Card Manager can not talk to smart card reader.",
    "Smart Card Manager can not establish a session with  the smart card.",
    "Smart Card Manager can not talk to Smart Card Server.",
    "Smart Card Manager can not talk to smart card reader."
 );    

function GetAuthDataFromPopUp(aKeyType,aKeyID,aUiData)
{

   keyUITable[aKeyID] = aUiData;
   keyTypeTable[aKeyID] = aKeyType;

   //alert("GetAuthDataFromPopUp data " + aUiData);
   var child = window.open("/GenericAuth.html",aKeyID,"height=400,width=400");

   //alert("Attempted to create child window " + child);
 
   curChildWindow = child; 

}

function COOLKeySetDataValue(aKeyType,aKeyID,name,value)
{
        //alert("In COOLKeySetDataValue  aKeyType " + aKeyType + " aKeyID " + aKeyID + " name " + name + " value " + value);  
        if(netkey)
        {
             try {
                    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
                netkey.SetCoolKeyDataValue(aKeyType,aKeyID,name,value);


            } catch(e) {
                MyAlert("Error Setting data values: " + e);
            }
        }

}
 
function COOLKeySetTokenPin(pin)
{
        if(netkey)
        {
             try { 
                netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
                netkey.SetCoolKeyDataValue(gCurKeyType,gCurKeyID,"TokenPin",pin);


            } catch(e) {
                MyAlert("Error Setting data values: " + e);
            }
        }
}

function COOLKeySetUidPassword(uid,pwd)
{

      if(netkey)
      {

          try {
              netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");

              netkey.SetCoolKeyDataValue(gCurKeyType,gCurKeyID,"UserId",uid);

              netkey.SetCoolKeyDataValue(gCurKeyType,gCurKeyID,"Password",pwd);

          } catch(e) {
              MyAlert("Error Setting data values: " + e);
          }

      }

}
      
  
function MyGetErrorMessage(status_code)
{

 var result = "Internal Server Error";

  if(status_code < 0 && status_code >= Status_Messages.length)
  {
     return result;
      
  }   
      
  return Status_Messages[status_code];
      
}   

function KeyToRowID(keyType, keyID)
{
  return keyType + "--" + keyID;
}

function RowIDToKeyInfo(rowID)
{
  return rowID.split("--");
}

function GetRowForKey(keyType, keyID)
{
  return document.getElementById(KeyToRowID(keyType, keyID));
}

function ReportException(msg, e)
{
  MyAlert(msg + " " + e.description + "(" + e.number + ")");
}

function GetCOOLKeyStatus(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    return netkey.GetCoolKeyStatus(keyType, keyID);
  } catch (e) {
    ReportException("netkey.GetCOOLKeyStatus() failed!", e);
    return 0;
  }
}

function GetCOOLKeyPolicy(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    return netkey.GetCoolKeyPolicy(keyType, keyID);
  } catch (e) {
  //  ReportException("netkey.GetCOOLKeyPolicy() failed!", e);
    return "";
  }
}

function GetCOOLKeyRequiresAuth(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    return netkey.GetCoolKeyRequiresAuthentication(keyType, keyID);
  } catch(e) {
    ReportException("netkey.GetCoolKeyRequiresAuthentication() failed!", e);
    return false;
  }
}

function GetCOOLKeyIsAuthed(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    return netkey.GetCoolKeyIsAuthenticated(keyType, keyID);
  } catch(e) {
    ReportException("netkey.GetCoolKeyIsAuthenticated() failed!", e);
    return false;
  }
}

function GetAvailableCOOLKeys()
{
  try {
    var keyArr;

      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
      var inArray = netkey.GetAvailableCoolKeys( {} );
      keyArr = new Array(inArray.length);
      var i;

      for (i=0; i < keyArr.length; i++) {
	keyArr[i] = new Array( "1", inArray[i]);
      }
    return keyArr;
  } catch(e) {
    ReportException("netkey.GetAvailableCoolKeys() failed!", e);
    return [];
  }
}

function EnrollCOOLKey(keyType, keyID, enrollmentType, screenname, pin,screennamepwd,tokencode)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    netkey.EnrollCoolKey(keyType, keyID, enrollmentType, screenname, pin,screennamepwd,tokencode);
  } catch(e) {
    ReportException("netkey.EnrollCoolKey() failed!", e);
    return false;
  }

  return true;
}

function GetCOOLKeyIsEnrolled(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    return netkey.GetCoolKeyIsEnrolled(keyType, keyID);
  } catch(e) {
    ReportException("netkey.GetCoolKeyIsEnrolled() failed!", e);
    return false;
  }
}

function CancelCOOLKeyOperation(keyType, keyID)
{
  try {
      netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    netkey.CancelCoolKeyOperation(keyType, keyID);
  } catch(e) {
    ReportException("netkey.CancelCoolKeyOperation() failed!", e);
    return false;
  }
  return true;
}

function MyAlert(message)
{
    if(message)
        DoMyAlert(message,"Smart Card Manager");

} 
function DoMyAlert(message,title)
{

   if(!message || !title)
       return;

   try {

       netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");

       var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"].getService(Components.interfaces.nsIPromptService);


       prompts.alert(window,title,message);

   } catch(e) {


       alert("Problem with nsIPromptService " + e);
   }

}

//
// MSHTML/GECKO compatibility functions.
//
function RemoveRow(table, row)
{
    table.deleteRow(row.rowIndex);
}

function GetCell(row, index)
{
  var cell;

    cell = row.cells[index];
  return cell;
}

function GetNode(parent, index)
{
  var node;
    node = parent.childNodes[index];
  return node;
}

function InsertRow(table)
{
  var row;

    row = table.insertRow(table.rows.length);
  return row;
}

function InsertCell(row)
{
  var cell;

    cell = row.insertCell(row.cells.length);
  return cell;
}

function RemoveAllChildNodes(parent)
{
  var numChildren = parent.childNodes.length;
  var i;

  i = numChildren;
  while (numChildren)
  {
    parent.removeChild(GetNode(parent,0));
    numChildren--;
  }

}


function UpdateInfoForKeyID(keyType, keyID, keyStatus, reqAuth, isAuthed)
{
  var row = GetRowForKey(keyType, keyID);

  if (!row)
    return;

  var cell = GetCell(row,1)
  RemoveAllChildNodes(cell);
  cell.appendChild(document.createTextNode(keyStatus));

//  cell = GetCell(row,2);
 // RemoveAllChildNodes(cell);
 // cell.appendChild(document.createTextNode(reqAuth));

 // cell = GetCell(row,3);
 // RemoveAllChildNodes(cell);
 // cell.appendChild(document.createTextNode(isAuthed));
}

function GetStatusForKeyID(keyType, keyID)
{
  var keyStatus = "BLANK";

  var status;

  try {
    status = GetCOOLKeyStatus(keyType, keyID);
  } catch(e) {
    status = 0;
  }

  switch (status) {
    case 0: // Unavailable
      keyStatus = "UNAVAILABLE";
      break;
    case 1: // AppletNotFound
      keyStatus = "NO APPLET";
      break;
    case 2: // Uninitialized
      keyStatus = "UNINITIALIZED";
      break;
    case 3: // Unknown
      keyStatus = "UNKNOWN";
      break;
    case 4: // Available
    case 6: // UnblockInProgress
    case 7: // PINResetInProgress
    case 8: // RenewInProgress
      keyStatus = PolicyToKeyType(GetCOOLKeyPolicy(keyType, keyID));
      break;
    case 5: // EnrollmentInProgress
      keyStatus = "BUSY";
      break;
      break;
    case 9: // FormatInProgress
      keyStatus = "BUSY";
      break;
  }

  return keyStatus;
}

function InsertCOOLKeyIntoBindingTable(keyType, keyID)
{
  var row = GetRowForKey(keyType, keyID);

  gWindow = window;
 if (!row)
  {
    var table = document.getElementById("BindingTable");
    if (table)
    {
      var keyStatus = GetStatusForKeyID(keyType, keyID);
      var keyReqAuth = BoolToYesNoStr(GetCOOLKeyRequiresAuth(keyType, keyID));
      var keyIsAuthed = BoolToYesNoStr(GetCOOLKeyIsAuthed(keyType, keyID));

      row = CreateTableRow(table, keyType, keyID, keyStatus, keyReqAuth, keyIsAuthed);
    }

    if (!row)
      return null;
  }

  return row;
}

function ConvertVariantArrayToJScriptArray(varr)
{
  // C++ native methods, like netkey.GetAvailableCOOLKeys(), can only
  // return variant SafeArrays, so to access the data inside, you must
  // first convert it to a VBArray, and then call toArray() to convert
  // it to a JScript array. Lame, but that's what it takes to
  // use an array returned from an ActiveX component.

  return new VBArray(varr).toArray();
}

function UpdateBindingTableAvailability()
{
  var arr = GetAvailableCOOLKeys();

  if (!arr || arr.length < 1)
    return;

  var i;

  for (i=0; i < arr.length; i++)
  {
    InsertCOOLKeyIntoBindingTable(arr[i][0], arr[i][1]);

    if (!gCurrentSelectedRow)
      SelectRowByKeyID(arr[i][0], arr[i][1]);
  }
}

function InitializeBindingTable()
{
  UpdateBindingTableAvailability();
  UpdateButtonStates();
}

function KeyIsPresent(keyType, keyID)
{
  row = document.all.item(keyType, keyID);

  if (!row)
    return false;

  return true;
}

function SetStatusMessage(str)
{
  var cell = document.getElementById("statusMsg");

  if (!cell)
    return;
  RemoveAllChildNodes(cell);
  cell.appendChild(document.createTextNode(str));
}

function UpdateButtonStates()
{
  if (gCurrentSelectedRow)
  {
    var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
    var keyType = keyInfo[0];
    var keyID = keyInfo[1];
    var keyStatus = GetStatusForKeyID(keyType, keyID);

    document.getElementById("enrollbtn").disabled = false;
  }
  else
  {
    document.getElementById("enrollbtn").disabled = true;
  }

  refresh();
}

function SetEnrollmentType(type)
{
  gKeyEnrollmentType = type;
  UpdateButtonStates();
}

function FindRow(node)
{
  while (node && node.tagName != "TR")
  {
    node = node.parentNode;
  }

  return node;
}

function SelectRow(row)
{
  if (!row || gCurrentSelectedRow == row)
    return;

  if (gCurrentSelectedRow)
    gCurrentSelectedRow.removeAttribute("style");

  gCurrentSelectedRow = row;
  gCurrentSelectedRow.style.backgroundColor="rgb(200,200,200)";
  UpdateButtonStates();
}

function SelectRowByKeyID(keyType, keyID)
{
  var row = GetRowForKey(keyType, keyID);
  SelectRow(row);
}

function DoSelectRow(event)
{
  var row;

    row = FindRow(event.parentNode);
  SelectRow(row);
}

function KeyToUIString(keyType, keyID)
{
  // If it's an COOLKey, format the keyID string.

  if (keyType == 1 && keyID.length == 20)
  {
    var re = /([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})/i;
    keyID = keyID.replace(re, "$1-$2-$3-$4-$5").toLowerCase();
  }

  return keyID;
}



function CreateTableRow(table, keyType, keyID, keyStatus, reqAuth, isAuthed)
{
  var row = InsertRow(table);
  if (!row)
    return null;

  row.setAttribute("id", KeyToRowID(keyType, keyID));
 
     row.onclick = DoSelectRow;

  // Create the key ID cell.
  //cell = InsertCell(row);
  //cell.appendChild(document.createTextNode(KeyToUIString(keyType, keyID)));

  //cell.setAttribute("onClick", "DoSelectRow(this);");

  // Create the keyStatus cell.
  //cell = InsertCell(row);
  //cell.appendChild(document.createTextNode(keyStatus));

  // Create the requires auth cell.
 // cell = InsertCell(row);
 // cell.appendChild(document.createTextNode(reqAuth));

  cell = InsertCell(row);
  cell.appendChild(document.createTextNode("Enrollment Progress"));

  // Create the status bar cell

  cell = InsertCell(row);

  var progressMeter = document.createElement("div");
  progressMeter.setAttribute("id", KeyToProgressBarID(keyType, keyID));
  progressMeter.className = "ProgressMeter";
  progressMeter.style.width = "100px";
  progressMeter.style.height = "1.5em";
//  progressMeter.style.visibility = "hidden";
  progressMeter.setAttribute("value", 0);

  var progressBar = document.createElement("div");
  progressBar.className = "ProgressBar";
  progressBar.style.width = "0px";
  progressBar.style.height = "100%";
//  progressBar.style.visibility = "hidden";

  var progressBarStatus = document.createElement("div");
  progressBarStatus.className = "ProgressBarStatus";
  progressBarStatus.appendChild(document.createTextNode(""));

  progressMeter.appendChild(progressBar);
  progressMeter.appendChild(progressBarStatus);
  cell.appendChild(progressMeter);

  //row.style.display ="none";

  return row;
}

gAnimationMSecs = 1000/30;

function SetCylonTimer(cylonID, cylonEyeID)
{
  setTimeout("AnimateCylonStatusBar(\"" + cylonID +
             "\", \"" + cylonEyeID + "\");", gAnimationMSecs);
}

function AnimateCylonStatusBar(cylonID, cylonEyeID)
{
  var cylon = document.getElementById(cylonID);

  if (!cylon)
    return;

  var active = cylon.getAttribute("cylonactive");

  if (!active)
    return;

  var eye = document.getElementById(cylonEyeID);

  if (!eye)
    return;

  var dir = eye.getAttribute("direction");
  var wid = parseInt(eye.style.width);
  var cywid = parseInt(cylon.style.width);
  var left = parseInt(eye.style.left);

  var dx = 10;

  if (!dir || dir >= 0)
  {
    left += dx;

    if (left + wid > cywid)
    {
      left = cywid - wid;
      eye.setAttribute("direction", "-1");
    }
  }
  else
  {
    left -= dx;

    if (left < 0)
    {
      left = 0;
      eye.setAttribute("direction", "1");
    }
  }

  eye.style.left = left + "px";

  SetCylonTimer(cylonID, cylonEyeID);
}

function StartCylonAnimation(cylonID, cylonEyeID)
{
  var cylon = document.getElementById(cylonID)

  if (!cylon)
    return;

  var active = cylon.getAttribute("cylonactive");

  if (!active)
  {
    cylon.setAttribute("cylonactive", "true");

    var eye = document.getElementById(cylonEyeID);
    if (eye)
    {
      eye.style.left = "0px";
      eye.style.visibility = "visible";
    }

    SetCylonTimer(cylonID, cylonEyeID);
  }
}

function StopCylonAnimation(cylonID, cylonEyeID)
{
  var cylon = document.getElementById(cylonID)

  if (cylon)
    cylon.removeAttribute("cylonactive");

  var eye = document.getElementById(cylonEyeID);

  if (eye)
    eye.style.visibility = "hidden";
}

function GetProgressMeterValue(progMeterID)
{
  var progMeter = document.getElementById(progMeterID);

  if (!progMeter)
    return -1;

  return parseInt(progMeter.getAttribute("value"));
}

function SetProgressMeterValue(progMeterID, value)
{
  var progMeter = document.getElementById(progMeterID);

  if (!progMeter || value < 0)
    return;

  if (value > 100)
    value = 100;

  var progBar = progMeter.firstChild;

  if (value == 0)
  {
    progBar.style.width = "0px";
    progBar.style.visibility = "hidden";
    progMeter.setAttribute("value", 0);
    return;
  }

  progBar.style.visibility = "visible"; 

  var newWidth = parseInt(progMeter.style.width) * value / 100 - 2;

  progBar.style.width =  newWidth + "px";
  progMeter.setAttribute("value", value);
}

function SetProgressMeterStatus(progMeterID, statusMsg)
{
  var progMeter = document.getElementById(progMeterID);

  if (!progMeter)
    return;

  var progBar = progMeter.firstChild;

  // If it exists, the meter status should be
  // div that is the next sibling of the progressMeter.

  var meterStatus = progBar.nextSibling;

  // Just replace the data in the text node, it's much faster,
  // and reduces flashing!

  meterStatus.firstChild.replaceData(0, meterStatus.firstChild.length, statusMsg);
}

function ClearProgressBar(progMeterID)
{
  SetProgressMeterValue(progMeterID, 0);
  SetProgressMeterStatus(progMeterID, "");
}

function KeyToProgressBarID(keyType, keyID)
{
  return "PM" + keyType + "-" + keyID;
}

////////////////////////////////////////////////////////////////
//
// Functions that contact the server or talk directly to
// ESC native code.
//
// ESC Native Functions:
//
//     netkey.GetAvailableCOOLKeys()
//
//       - Returns an ActiveX Variant SafeArray containing the ID for each key
//         that is currentlly plugged into the computer. Before accessing any
//         data in this array you must convert it to a JScript Array with a
//         call to ConvertVariantArrayToJScriptArray().
//
//     netkey.GetCOOLKeyIsEnrolled(keyType, keyID)
//
//       - Returns true if a key has been initialized, false if it hasn't.
//         Initialized means the card has been formatted with certificates
//         for either an COOL HouseKey or NetKey.
//
//     netkey.EnrollCOOLKey(keyType, keyID, enrollmentType, screenName, pin)
//
//       - Initiates an async connection to the RA to initialize a specific
//         key. If you want the key to be initialized as a HouseKey, you should
//         pass "houseKey" as the enrollmentType, and null values for both
//         screenName and pin. For a NetKey, use "netKey" as the enrollmentType,
//         and pass a valid screenName and pin.
//
//
////////////////////////////////////////////////////////////////

function GetScreenNameValue()
{
  var sname = document.getElementById("snametf").value;

  if (! sname)
  {
    MyAlert("You must provide a valid LDAP User ID!");
    return null;
  }

  return sname;
}

function GetPINValue()
{
  var pinVal =  document.getElementById("pintf").value;
  var rpinVal =  document.getElementById("reenterpintf").value;

  if (! pinVal)
  {
    MyAlert("You must provide a valid Key Password!");
    return null;
  }

  if ( pinVal != rpinVal)
  {
    MyAlert("The Key Password values you entered do not match!");
    return null;
  }

  return pinVal;
}

function GetScreenNamePwd()
{

  var pwd = document.getElementById("snamepwd").value;

   if(!pwd)
   {
       MyAlert("You must provide a valid LDAP User ID !");
       return null;
   }
   return pwd;
}

function GetTokenCode()
{

  return null;
}
function DoEnrollCOOLKey()
{

  if (!gCurrentSelectedRow)
  {
    MyAlert("Please select a key.");
    return;
  }


 if(!Validate())
     return;

  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  var type = gKeyEnrollmentType;
  var screenname = null;
  var pin = null;

  var screennamepwd = null;
  var tokencode = null;

  if (type == "userKey")
  {
    screenname =  GetScreenNameValue();

    pin =  GetPINValue();


    screennamepwd =  GetScreenNamePwd();

    tokencode = GetTokenCode();

    //SetStatusMessage("Enrolling UserKey \"" + KeyToUIString(keyType, keyID) + "\"...");
  }

  StartCylonAnimation("cylon1", "eye1");    

  var doShow = true;

  ShowProgressBar(keyType,keyID,doShow );

  if (!EnrollCOOLKey(keyType, keyID, type, screenname, pin,screennamepwd,tokencode))
  {
    SetStatusMessage("");
    StopCylonAnimation("cylon1", "eye1");
    var doShow = false;
    ShowProgressBar(aKeyType,aKeyID,doShow );
  }
}

function DoResetSelectedCOOLKeyPIN()
{
  if (!gCurrentSelectedRow)
    return;

  if(!Validate())
     return;

   //alert("In DoResetSelectedCOOLKeyPIN!");
  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  var screenname = null;
  var pin = null;
  var screennamepwd = null;

  if (GetCOOLKeyIsEnrolled(keyType, keyID))
  {
 
    SetStatusMessage("Resetting PIN for \"" + keyID + "\"...");
    StartCylonAnimation("cylon1", "eye1");

    if (!ResetCOOLKeyPIN(keyType, keyID, screenname, pin,screennamepwd))
    {
      SetStatusMessage("");
      StopCylonAnimation("cylon1", "eye1");
    }
  }
}

function DoFormatCOOLKey()
{
  if (!gCurrentSelectedRow)
    return;


  if(!Validate())
     return;


  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  var type = gKeyEnrollmentType;
  var screenname = null;
  var pin = null;

  var screennamepwd = null;
  var tokencode = null;

  SetStatusMessage("Formatting \"" + KeyToUIString(keyType, keyID) + "\" ...");
  StartCylonAnimation("cylon1", "eye1");

  if (!FormatCOOLKey(keyType, keyID, type, screenname, pin,screennamepwd,tokencode))
  {
    SetStatusMessage("");
    StopCylonAnimation("cylon1", "eye1");
  }
}
function DoCancelOperation()
{

  if (!gCurrentSelectedRow)
    return;

  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  SetStatusMessage("Cancel operation for \"" + KeyToUIString(keyType, keyID) + "\" ...");
  StartCylonAnimation("cylon1", "eye1");

  CancelCOOLKeyOperation(keyType, keyID);

  SetStatusMessage("");
  StopCylonAnimation("cylon1", "eye1");
}

function DoChallengeSelectedKey()
{
  if (!gCurrentSelectedRow)
    return;

  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  if (!keyID)
    return;

  SetStatusMessage("Generating Challenge ...");

  var challengeArray = ChallengeCOOLKey(keyType, keyID, document.forms[0].challengedata.value);

  if (challengeArray.length != 4)
  {
    MyAlert("Challenge for key \"" + KeyToUIString(keyType, keyID) + "\" failed!");
    SetStatusMessage("");
    return;
  }

  MyAlert("ChallengeCOOLKey(\""+ KeyToUIString(keyType, keyID) + "\") returned:\n\n" +
        "challenge[0]: " + challengeArray[0] + "\n" +
        "challenge[1]: " + challengeArray[1] + "\n" +
        "challenge[2]: " + challengeArray[2] + "\n" +
        "challenge[3]: " + challengeArray[3] + "\n");

  SetStatusMessage("");
}

function DoBlinkCOOLKey()
{
  if (!gCurrentSelectedRow)
    return;

  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  if (!keyID)
    return;

  SetStatusMessage("Blinking \"" + KeyToUIString(keyType, keyID) + "\" ...");
  StartCylonAnimation("cylon1", "eye1");

  BlinkCOOLKey(keyType, keyID, 400, 5000);

  StopCylonAnimation("cylon1", "eye1");
  SetStatusMessage("");
}

function OnCOOLKeyBlinkComplete(keyType,keyID)
{
  //StopCylonAnimation("cylon1", "eye1");
  //SetStatusMessage(" ");
}

function DoHelp()
{
  if (!gCurrentSelectedRow)
    return;

  var keyInfo = RowIDToKeyInfo(gCurrentSelectedRow.getAttribute("id"));
  var keyType = keyInfo[0];
  var keyID = keyInfo[1];

  if (!keyID)
    return;

  var policy = GetCOOLKeyPolicy(keyType, keyID);
  var type = PolicyToKeyType(policy);
  MyAlert("Policy:  " + policy + "\n" + "Type:    " + type);
}

////////////////////////////////////////////////////////////////
//
// Functions called directly from ASC native code.
//
////////////////////////////////////////////////////////////////

function OnCOOLKeyInserted(keyType, keyID)
{
  var row = InsertCOOLKeyIntoBindingTable(keyType, keyID);

  if (!gCurrentSelectedRow)
    SelectRowByKeyID(keyType, keyID);
}


function OnCOOLKeyRemoved(keyType, keyID)
{
  var row = GetRowForKey(keyType, keyID);
  var table = document.getElementById("BindingTable");

  if (row && table)
  {
    RemoveRow(table,row);

    if (row == gCurrentSelectedRow)
      gCurrentSelectedRow = null;
  }

  UpdateButtonStates();
}

var gKnownPolicies = [

  // OID Value, precedence, name value

  [ "OID.1.3.6.1.4.1.1066.1.1000.1.0.1.1", 1, "HOUSEKEY" ], // Bronze   - HouseKey
  [ "OID.1.3.6.1.4.1.1066.1.1000.1.0.1.2", 2, "NETKEY" ],   // Silver   - Member
  [ "OID.1.3.6.1.4.1.1066.1.1000.1.0.1.3", 3, "NETKEY" ],   // Gold     - Associate
  [ "OID.1.3.6.1.4.1.1066.1.1000.1.0.1.4", 4, "NETKEY" ],   // Platinum - MyDoctor

  // XXX: Remove the Old OIDs below, after the RA starts generating
  //      certificates with the OIDs listed above!
  [ "OID.1.3.6.1.4.1.1066.1.1000.2.1", 1, "HOUSEKEY" ], // Bronze   - HouseKey
  [ "OID.1.3.6.1.4.1.1066.1.1000.2.2", 2, "NETKEY" ],   // Silver   - Member
  [ "OID.1.3.6.1.4.1.1066.1.1000.2.3", 3, "NETKEY" ],   // Gold     - Associate
  [ "OID.1.3.6.1.4.1.1066.1.1000.2.4", 4, "NETKEY" ]    // Platinum - MyDoctor
];

function PolicyToKeyType(policy)
{
   return "ENROLLED";
}

function OldPolicyToKeyType(policy)
{
  var i, j;
  
  var knownPoliciesIndex = -1;

  
  var policies;


  if (policy.indexOf(",")== -1)
  {
    policies = new Array(1);
    policies[0] = policy;
  }
  else
  {
    policies = policy.split(",");
  }

  for (j = 0; j < policies.length; j++)
  {
    for (i = 0; i < gKnownPolicies.length; i++)
    {
      if (gKnownPolicies[i][0] == policies[j])
      {
         if (knownPoliciesIndex < gKnownPolicies[i][1])
           knownPoliciesIndex = i;
      }
    }  
  }

  if (knownPoliciesIndex == -1)
    return "INITIALIZED";
 
  return gKnownPolicies[knownPoliciesIndex][2];    
}

function BoolToYesNoStr(b)
{
  if (b)
    return "YES";
  return "NO";
}

function OnCOOLKeyEnrollmentComplete(keyType, keyID)
{
  var keyStatus = PolicyToKeyType(GetCOOLKeyPolicy(keyType, keyID));
  var keyReqAuth = BoolToYesNoStr(GetCOOLKeyRequiresAuth(keyType, keyID));
  var keyIsAuthed = BoolToYesNoStr(GetCOOLKeyIsAuthed(keyType, keyID));

  //UpdateInfoForKeyID(keyType, keyID, keyStatus, keyReqAuth, keyIsAuthed);
  UpdateButtonStates();

  StopCylonAnimation("cylon1", "eye1");
  var doShow = false;
  ShowProgressBar(keyType,keyID, doShow);
  SetStatusMessage("");
  MyAlert("Enrollment of smartcard complete!");
  ClearProgressBar(KeyToProgressBarID(keyType, keyID));

  window.setTimeout("loadSuccessPage()",4);
}

function OnCOOLKeyPINResetComplete(keyType, keyID)
{
  var keyStatus = PolicyToKeyType(GetCOOLKeyPolicy(keyType, keyID));
  var keyReqAuth = BoolToYesNoStr(GetCOOLKeyRequiresAuth(keyType, keyID));
  var keyIsAuthed = BoolToYesNoStr(GetCOOLKeyIsAuthed(keyType, keyID));

  UpdateInfoForKeyID(keyType, keyID, keyStatus, keyReqAuth, keyIsAuthed);
  UpdateButtonStates();

  StopCylonAnimation("cylon1", "eye1");
  SetStatusMessage("");
  MyAlert("Password Reset was successful!");
  ClearProgressBar(KeyToProgressBarID(keyType, keyID));
}

function OnCOOLKeyFormatComplete(keyType, keyID)
{
  var keyStatus = GetStatusForKeyID(keyType, keyID);
  var keyReqAuth = BoolToYesNoStr(GetCOOLKeyRequiresAuth(keyType, keyID));
  var keyIsAuthed = BoolToYesNoStr(GetCOOLKeyIsAuthed(keyType, keyID));

  UpdateInfoForKeyID(keyType, keyID, keyStatus, keyReqAuth, keyIsAuthed);

  StopCylonAnimation("cylon1", "eye1");
  SetStatusMessage("");
  MyAlert("Format of \"" + KeyToUIString(keyType, keyID)+ "\" was successful!");
  ClearProgressBar(KeyToProgressBarID(keyType, keyID));
}

function OnCOOLKeyStateError(keyType, keyID, keyState, errorCode)
{
  var keyStatus = GetStatusForKeyID(keyType, keyID);
  var keyReqAuth = BoolToYesNoStr(GetCOOLKeyRequiresAuth(keyType, keyID));
  var keyIsAuthed = BoolToYesNoStr(GetCOOLKeyIsAuthed(keyType, keyID));

  if(curChildWindow)
  {
      curChildWindow.close();
      curChildWindow = null;

  }

  var doShow = false;
  ShowProgressBar(keyType,keyID, doShow);

  //UpdateInfoForKeyID(keyType, keyID, keyStatus, keyReqAuth, keyIsAuthed);

  StopCylonAnimation("cylon1", "eye1");
  SetStatusMessage("");

  var typeStr = "Error(" + errorCode + ")";

  var  messageStr = " \n\n Error Response: " + MyGetErrorMessage(errorCode) ;

  var keyIDStr = KeyToUIString(keyType, keyID);

  if (keyState == 1004)
    typeStr = "Enrollment of key  failed. " + typeStr + messageStr ;
  else if (keyState == 1016)
    typeStr = "Formatting of key  failed. " + typeStr + messageStr;
  else if (keyState == 1010)
    typeStr = "PIN Reset for key  failed. " + typeStr + messageStr;
  else if (keyState == 1020)
    typeStr = "Operation for key  canceled.";

  typeStr += " \n " + ErrorText;
  MyAlert(typeStr);
  ClearProgressBar(KeyToProgressBarID(keyType, keyID));
}

function OnCOOLKeyStatusUpdate(progMeterID, statusUpdate)
{
  SetProgressMeterValue(progMeterID, statusUpdate);
  SetProgressMeterStatus(progMeterID, statusUpdate + "%");
}

function Validate()
{

  var type = gKeyEnrollmentType;
  var screenname = null;
  var pin = null;

  var screennamepwd = null;
  var tokencode = null;

  if (type == "userKey")
  {
    screenname = GetScreenNameValue();
    if (! screenname)
      return 0;

    screennamepwd = GetScreenNamePwd();

    if(! screennamepwd)
        return 0;

    pin =  GetPINValue();

    if (! pin)
      return 0;

   }

   return 1;
}

function OnCOOLKeyStateChange(keyType, keyID, keyState, data,strData)
{
  // alert("KeyID:    " + keyID + "\n" +
  //       "KeyState: " + keyState + "\n" +
  //       "Data:     " + data);
  //alert("State Change ="+keyState);

  switch(keyState)
  {
    case 1000: // KeyInserted
      OnCOOLKeyInserted(keyType, keyID);
      break;
    case 1001: // KeyRemoved
      OnCOOLKeyRemoved(keyType, keyID);
      break;
    case 1002: // EnrollmentStart
      // OnCOOLKeyEnrollmentStart(keyType, keyID);
      break;
    case 1003: // EnrollmentComplete
      OnCOOLKeyEnrollmentComplete(keyType, keyID);
      break;
    case 1004: // EnrollmentError
      OnCOOLKeyStateError(keyType, keyID, keyState, data);
      break;
    case 1008: // PINResetStart
      // OnCOOLKeyPINResetStart(keyType, keyID);
      break;
    case 1009: // PINResetComplete
      OnCOOLKeyPINResetComplete(keyType, keyID);
      break;
    case 1010: // PINResetError
      OnCOOLKeyStateError(keyType, keyID, keyState, data);
      break;
    case 1014: // FormatStart
      // OnCOOLKeyFormatStart(keyType, keyID);
      break;
    case 1015: // FormatComplete
      OnCOOLKeyFormatComplete(keyType, keyID);
      break;
    case 1016: // FormatError
      OnCOOLKeyStateError(keyType, keyID, keyState, data);
      break;
    case 1017: // BlinkStatus Update?
      //OnCOOLKeyStateError(keyType, keyID, keyState, data);
      break;
    case 1018: 
      OnCOOLKeyBlinkComplete(keyType, keyID);
      break;
    case 1020: // OperationCancelled
      OnCOOLKeyStateError(keyType, keyID, keyState, data);
      break;
    case 1021: // OperationStatusUpdate
      OnCOOLKeyStatusUpdate(KeyToProgressBarID(keyType, keyID), data);
      break;

     case 1022: //Need Auth 


       gCurKeyID = keyID;
       gCurKeyType = keyType;

       GetAuthDataFromPopUp(keyType,keyID,strData);

       break;

  }
}

function refresh()
{
  window.resizeBy(0,1);
  window.resizeBy(0,-1);

}

function loadSuccessPage()
{
    window.location="/esc/home/EnrollSuccess.html";
}

function ShowProgressBar(aKeyType,aKeyID, doShow)
{
   if(!gCurrentSelectedRow)
      return;

   if(doShow)
       gCurrentSelectedRow.style.display="table-row";
   else
   {
       gCurrentSelectedRow.style.display="none";
   }
}
