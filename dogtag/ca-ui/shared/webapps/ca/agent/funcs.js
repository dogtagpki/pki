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

//<!--
function doubleQuotes(componentName)
{
    for (i=0; i < componentName.length; i++) {
        if (componentName.charAt(i) == '"') {
            return true;
        }
    }
    return false;
}

function escapeDNComponent(str)
{
    var outStr = "";
    var escapeValue = false;

    // Do we need to escape any characters
    for (i=0; i < str.length; i++) {
        c = str.charAt(i);
        if (c == ',' || c == '=' || c == '+' || c == '<' ||
            c == '>' || c == '#' || c == ';' || c == '\r' ||
            c == '\n') {
            escapeValue = true;
            break;
        }
    }

    if (escapeValue == true) {
        outStr += '"';
        outStr += str;
        outStr += '"';
    } else {
        outStr += str;
    }
    return outStr;
}

function formulateDN(form, distinguishedName)
{
    with (form) {
        distinguishedName.value = '';
	if (form.eMail != null) {
	    if (eMail.value != '') {
		if (doubleQuotes(eMail.value) == true) {
		    alert('Double quotes are not allowed in the E-mail field');
		    eMail.value = '';
		    eMail.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'E=' + escapeDNComponent(eMail.value);
	    }
	}
	if (form.commonName != null) {
	    if (commonName.value != '') {
		if (doubleQuotes(commonName.value) == true) {
		    alert('Double quotes are not allowed in Common Name field');
		    commonName.value = '';
		    commonName.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'CN=' + escapeDNComponent(commonName.value);
	    }
        }
	if (form.userID != null) {
	    if (userID.value != '') {
		if (doubleQuotes(userID.value) == true) {
		    alert('Double quotes are not allowed in the user id field');
		    userID.value = '';
		    userID.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'UID=' + escapeDNComponent(userID.value);
	    }
        }
	if (form.orgUnit != null) {
	    if (orgUnit.value != '') {
		if (doubleQuotes(orgUnit.value) == true) {
		    alert('Double quotes are not allowed in Org Unit field');
		    orgUnit.value = '';
		    orgUnit.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'OU=' + escapeDNComponent(orgUnit.value);
	    }  
        }
	if (form.org != null) {
	    if (org.value != '') {
		if (doubleQuotes(org.value) == true) {
		    alert('Double quotes are not allowed in Organization field.');
		    org.value = '';
		    org.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'O=' + escapeDNComponent(org.value);
	    }  
	}
	if (form.locality != null) {
	    if (locality.value != '') {
		if (doubleQuotes(locality.value) == true) {
		    alert('Double quotes are not allowed in Locality field.');
		    locality.value = '';
		    locality.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'L=' + escapeDNComponent(locality.value);
	    }
	}
	if (form.state != null) {
	    if (state.value != '') {
		if (doubleQuotes(state.value) == true) {
		    alert('Double quotes are not allowed in State field.');
		    state.value = '';
		    state.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'ST=' + escapeDNComponent(state.value);
	    }
	}
	if (form.country != null) {
	    if (country.value != '') {
		if (doubleQuotes(country.value) == true) {
		    alert('Double quotes are not allowed in Country field.');
		    country.value = '';
		    country.focus();
		    return;
		}
		if (distinguishedName.value != '') distinguishedName.value += ', ';
		distinguishedName.value += 'C=' + escapeDNComponent(country.value);
	    }
	}
    }
}

function isValidIssuerDN(form)
{
    if ((form.orgUnit.value == '') && (form.org.value == '')) {
        alert("You must enter an Organization Unit or an Organization.");
        return false;
    } else {
        return true;
    }
}

function isValidAdminDN(form)
{

    if (form.commonName.value == '') {
        alert("You must enter a Common Name.");
        return false;
    } else {
        return true;
    }
}

function isValidCSR(form)
{
    // Note: the checks here are of mixed origin.  Some are required for Navigator
    // and Communicator.  The CSR field checks are to avoid server side rejection of the
    // submission.  These checks can be split up to be different for different types of
    // certificates.
    
    formulateDN(form, form.subject);

    with (form) {
	if (isEmailCert != null) {
	   if (eMail.value == "" && isEmailCert.checked) {
              alert("E-mail certificates must include an E-mail address.");
	      return false;
	   }
        }
        if (commonName.value == "") {
            alert("You must supply your name for the certificate.");
            return false;
        }
        if (csrRequestorName.value == "") {
            csrRequestorName.value = commonName.value;
        }
        if (csrRequestorPhone.value == "" && csrRequestorEmail.value == "") {
            alert("You must supply a contact phone number or e-mail address.");
            return false;
        }
        return true;
    }
}

function isNegative(string) {
  if (string.charAt(0) == '-')
     return true;
  else
     return false;
}

function isNumber(string, radix) {
  var i = 0; 
  var legalDigits;
  if (radix == null || radix == 10) {
     legalDigits = "0123456789";
  } else if (radix == 16) {
     legalDigits = "0123456789abcdefABCDEF:";
  } else {
     return false;
  }
  for(; i < string.length; ++i) {
     if (string.charAt(i) != ' ')
     	break;
  }
  if (string.charAt(i) == '+' || string.charAt(i) == '-' ) {
     ++i;
  }
  if (radix == 16 && i < string.length - 2 &&
      string.charAt(i) == '0' &&
      (string.charAt(i+1) == 'x' || string.charAt(i+1) == 'X') &&
      legalDigits.indexOf(string.charAt(i+2)) != -1) {
	i += 3;
  }
  for(; i < string.length; ++i) {
     if (legalDigits.indexOf(string.charAt(i)) == -1)
     	break;
  }
  for(; i < string.length; ++i) {
     if (string.charAt(i) != ' ')
     	return false;
  }
  return true;
}

function isDecimalNumber(string) {
    var i = 0; 
    var legalDigits = "0123456789";

    for (; i < string.length; i++) {
        if (string.charAt(i) != ' ')
            break;
    }
    if (i < string.length &&
        legalDigits.indexOf(string.charAt(i)) != -1) {
        i++;
    } else
        return false;

    for (; i < string.length; i++) {
        if (legalDigits.indexOf(string.charAt(i)) == -1)
            break;
    }
    for (; i < string.length; i++) {
        if (string.charAt(i) != ' ')
            return false;
    }

    return true;
}

function isHexNumber(string) {
    var i = 0; 
    var legalDigits = "0123456789abcdefABCDEF";

    for (; i < string.length; i++) {
        if (string.charAt(i) != ' ')
            break;
    }
    if (i < string.length - 2 &&
        string.charAt(i) == '0' &&
        (string.charAt(i+1) == 'x' || string.charAt(i+1) == 'X') &&
        legalDigits.indexOf(string.charAt(i+2)) != -1) {
        i += 3;
    } else
        return false;

    for (; i < string.length; i++) {
        if (legalDigits.indexOf(string.charAt(i)) == -1)
            break;
    }
    for (; i < string.length; i++) {
        if (string.charAt(i) != ' ')
            return false;
    }

    return true;
}

function trim(string) {
    var i, k, newString;

    for (i = 0; i < string.length; i++) {
        if (string.charAt(i) != ' ' )
            break;
    }
    for (k = string.length - 1; k > i; k--) {
        if (string.charAt(k) != ' ' )
            break;
    }
    k++;

    if (k > i)
        newString = string.substring(i, k);
    else
        newString = null;

    return  newString;
}


function dateForm(name)
{
	var i;
	document.write('<FORM NAME=\"'+ name +'\">');
	document.write('<SELECT NAME=\"day\"><OPTION VALUE=0> ');
	for (i=1; i <=31; ++i)
		document.write('<OPTION VALUE='+i+'>'+i);
	document.write('</SELECT>');
	document.write('<SELECT NAME=\"month\">'+
		'<OPTION VALUE=13> '+
		'<OPTION VALUE=0>January'+
		'<OPTION VALUE=1>February'+
		'<OPTION VALUE=2>March'+
		'<OPTION VALUE=3>April'+
		'<OPTION VALUE=4>May'+
		'<OPTION VALUE=5>June'+
		'<OPTION VALUE=6>July'+
		'<OPTION VALUE=7>August'+
		'<OPTION VALUE=8>September'+
		'<OPTION VALUE=9>October'+
		'<OPTION VALUE=10>November'+
		'<OPTION VALUE=11>December'+
		'</SELECT>'
	);
	
	document.write('<SELECT NAME=\"year\"><OPTION VALUE=0> ');
	for (i=1996; i <=2006; ++i)
		document.write('<OPTION VALUE='+i+'>'+i);
	document.write('</SELECT>');
	document.write('</FORM>');
}

function dateIsEmpty(form)
{
     return form.day.selectedIndex == 0  && 
            form.month.selectedIndex == 0 &&
	    form.year.selectedIndex == 0;
}
 

function convertDate(form, fieldName)
{
     var date;
     var day = form.day.options[form.day.selectedIndex].value;
     var month = form.month.options[form.month.selectedIndex].value;
     var year = form.year.options[form.year.selectedIndex].value;
     date = new Date(year,month,day);

     // see if normalization was required
     if (date.getMonth() != month || date.getDate() != day || year == 0) {
        alert(fieldName + " is invalid");
        return null;
     }
     else 
     	return date.getTime();
//     	return Math.round(date.getTime() / 1000);
}

function convertToTime(form)
{
     var date;
     var day = form.day.options[form.day.selectedIndex].value;
     var month = form.month.options[form.month.selectedIndex].value;
     var year = form.year.options[form.year.selectedIndex].value;
     date = new Date(year,month,day);

     // see if normalization was required
     if (date.getMonth() != month || date.getDate() != day) {
        return null;
     }
     else
        return date.getTime();
}

function daysToSeconds(days){
    return 3600 * 24 * days;
}
 
function clickedOnTimeRangeCheckBox(inUse, start, end)
{
    if (inUse.checked) {
        var date = new Date();
        if (start.day.options[start.day.selectedIndex].value == 0) {
            start.day.selectedIndex = date.getDate();
        }
        if (end.day.options[end.day.selectedIndex].value == 0) {
            end.day.selectedIndex = date.getDate();
        }
        if (start.month.options[start.month.selectedIndex].value == 13) {
            start.month.selectedIndex = date.getMonth() + 1;
        }
        if (end.month.options[end.month.selectedIndex].value == 13) {
            end.month.selectedIndex = date.getMonth() + 1;
        }
        if (start.year.options[start.year.selectedIndex].value == 0) {
            for (var i = 0; i < start.year.options.length; i++) {
                if (start.year.options[i].value == date.getFullYear()) {
                    start.year.selectedIndex = i;
                }
            }
        }
        if (end.year.options[end.year.selectedIndex].value == 0) {
            for (var i = 0; i < end.year.options.length; i++) {
                if (end.year.options[i].value == date.getFullYear()) {
                    end.year.selectedIndex = i;
                }
            }
        }
    }
}

function generateYearOptions(before, after)
{
    var now = new Date();
    var year = now.getFullYear();
    document.writeln("<OPTION VALUE=0>");
    for (var i = year-before-1; i < year+after+1; i++) {
        document.writeln("<OPTION VALUE="+i+">"+i);
    }
}

// encloses value in double quotes preceding all embedded double quotes with \
function escapeValue(value)
{
    var result;
    var fromIndex = 0, toIndex = 0;

    // kludgy work-around for indexOf JavaScript bug on empty string
    if (value == "")
        return '\"\"';
    
    result = '\"';
    while ((toIndex = value.indexOf('\"',fromIndex)) != -1) {
    	result += value.substring(fromIndex,toIndex);
     	result += '\\"';
	fromIndex = toIndex + 1;
    }
    result += value.substring(fromIndex,value.length);
    result += '\"';
    return result;
}

// encloses value in double quotes preceding all embedded double quotes and 
// backslashes with backslash
function escapeValueJSString(value)
{
    var result = "";

    // Do we need to escape any characters
    for (i=0; i < value.length; i++) {
        c = value.charAt(i);
        if (c == '\\' | c == '"') {
			result += '\\';
        }
		result += c;
    }
    return '\"' + result + '\"';
}

function escapeValueRfc1779(value)
{
    var result = "";

    // Do we need to escape any characters
    for (i=0; i < value.length; i++) {
        c = value.charAt(i);
        if (c == ',' || c == '=' || c == '+' || c == '<' ||
            c == '>' || c == '#' || c == ';' || c == '\r' ||
            c == '\n' || c == '\\' || c == '"') {
			result += '\\';
        }
		result += c;
    }
    return result;
}

// helper function to construct name component(pattern)
function makeComponent(list,tag,value,asPattern)
{
   var last = list.length;
//   if (asPattern) { 
//   	list[last] = (value == "") ? "*" : (tag+"="+escapeValueRfc1779(value));
//   }
//   else if (value != "")
   if (value != "") {
      list[last] = tag+"="+escapeValueRfc1779(value);
//   } else if (!asPattern) {
//      list[last] = tag+"=*";
   }
//   alert("asPattern = " + asPattern);
}

// If asPattern is false formulates the RFC 1779 format subject name 
// from the component parts skipping all components with blank values,
// otherwise builds RFC 1779-like matching pattern from components
function computeNameCriterion(form)
{
    var asPattern = form.match[1].checked;
    var result = new Array;

	with (form) {
	// The order of clauses here determines how components are ordered
	// in the name sent in the client's request.  A site may wish to
	// re-order the clauses here if their conventions produce names
	// with components in a different order.
		makeComponent(result,"E",eMail.value,asPattern);
		makeComponent(result,"CN",commonName.value,asPattern);
		makeComponent(result,"UID",userID.value,asPattern);
		makeComponent(result,"OU",orgUnit.value,asPattern);
		makeComponent(result,"O",org.value,asPattern);
		makeComponent(result,"L",locality.value,asPattern);
		makeComponent(result,"ST",state.value,asPattern);
		makeComponent(result,"C",country.value,asPattern);
	}
    if (result.length == 0)
//    	return asPattern ? "0 == 0" : "0 == 1";
    	return "(x509Cert.subject=*)";
    else  {
        return "(x509Cert.subject" + (asPattern ? "~=" : "=") + escapeValue(nsjoin(result,",")) + ")";
        }
// escapeValue(result.join(', '));
}

// helper function to construct name component(pattern)
function makeComponentFilter(list,tag,value,asPattern)
{
   var last = list.length;
   if (value != "") {
	if (asPattern) {
		list[last] = "(x509Cert.subject=*"+tag+"=*"+
			escapeValueRfc1779(value)+"*)";
	} else {
		// exact match (either the end, or appended with ",")
		list[last] = "(|(x509Cert.subject=*"+tag+"="+
			escapeValueRfc1779(value)+",*)"
			+"(x509Cert.subject=*"+tag+"="+
			escapeValueRfc1779(value)+"))";
	}
   }
}

function computeNameFilter(form)
{
    var asPattern = form.match[1].checked;
    var result = new Array;

	with (form) {
	// The order of clauses here determines how components are ordered
	// in the name sent in the client's request.  A site may wish to
	// re-order the clauses here if their conventions produce names
	// with components in a different order.
		makeComponentFilter(result,"E",eMail.value,asPattern);
		makeComponentFilter(result,"CN",commonName.value,asPattern);
		makeComponentFilter(result,"UID",userID.value,asPattern);
		makeComponentFilter(result,"OU",orgUnit.value,asPattern);
		makeComponentFilter(result,"O",org.value,asPattern);
		makeComponentFilter(result,"L",locality.value,asPattern);
		makeComponentFilter(result,"ST",state.value,asPattern);
		makeComponentFilter(result,"C",country.value,asPattern);
	}
	if (result.length == 0) {
		return "(x509Cert.subject=*)";
	} else  {
		if (asPattern) {
        		return "(|" + nsjoin(result,"") + ")";
		} else {
        		return "(&" + nsjoin(result,"") + ")";
		}
	}
}

function booleanCrit(crit,radioArg)
{
    for (var i = 0; i < radioArg.length; ++i ){
       if( radioArg[i].checked ) {
          if (radioArg[i].value.length != 0) {
	     crit[crit.length] = radioArg[i].name + " == " + radioArg[i].value;
          }
	  return;
       }
    }
}

function isHTTPEscapeChar(c)
{
    if (c == '%' || c == '#' || c == '+' || c == '=' || c == '\n' ||
        c == '\r' || c == '\t' || c == ';' || c == '&' ||
        c == '>') {
        return true;
    }

    return false;
}

function produceHTTPEscapedString(inString)
{
    table = new Object();
    table["%"] = "25";
    table["#"] = "23";
    table["+"] = "2B";
    table["="] = "3D";
    table["\n"] = "0A";
    table["\r"] = "0D";
    table["\t"] = "09";
    table[";"] = "3B";
    table["&"] = "26";
    table[">"] = "3E";

    outString = "";

    for (i=0; i < inString.length; i++) {
        if (inString.charAt(i) == ' ') {
            outString += '+';
        } else {
            if (isHTTPEscapeChar(inString.charAt(i))) {
                outString += "%" + table[inString.substring(i, i+1)];
            } else {
                outString += inString.charAt(i);
            }
        }
    }

    return outString;
}

function isHex(string)
{
      if (string.charAt(0) == '0' &&
      (string.charAt(1) == 'x' || string.charAt(1) == 'X')) {
        return true;
      } else {
        return false;
      }
}

function writeError(errorDetails)
{
        document.write("<center><h2><b>" +
                "Problem Processing Your Request" +
                "</b></h2></center><p>" +
                "The service encountered a problem " +
                "when processing your request. This problem may " +
                "indicate a flaw in the form used to submit your " +
                "request or the values that were entered into the form." +
                "The following message supplies more information " +
                "about the error that occurred.<p>");
        document.write("<blockquote><b><pre>");
        if (errorDetails != null) {
                document.write(errorDetails);
        } else {
                document.write("Unable to provide details. " +
                 "Contact Administrator.");
        }
        document.write("</pre></b></blockquote>");
        if (result.header.errorDescription != null) {
                document.write('<p>Additional Information:<p>');
                document.write('<blockquote><b>');
                document.write(result.header.errorDescription);
                document.write('</b></blockquote>');
        }
        document.write("<p>");
        document.write("Please consult your local administrator for " +
                "further assistance.");
        document.write("The certificate server's log may provide " +
              "further information.");
}

// strips (optional) spaces and 0[xX] prefix at the beginning of s
function stripPrefix(s)
{
  var i;
  for(i = 0; i < s.length - 1; ++i) {
     if (s.charAt(i) != ' ' )
	break;
  }
  if (s.charAt(i) == '0' && (s.charAt(i+1) == 'x' || s.charAt(i+1) == 'X')) {
	return s.substring(i+2,s.length);
  } else {
  	return  s.substring(i,s.length);;
  }
}

// removes colons from value and returns the result
// used as helper to convert colon-separated hexadecimal numbers
// to regular numbers
function removeColons(value)
{
    var result = "";

    for (i=0; i < value.length; i++) {
        c = value.charAt(i);
        if (c != ':' ){
		result += c;
        }
    }
    return result;
}

// Replacement for the array.join() function which isn't in MSIE 3.0

function nsjoin(array,str) {
  val = "";
  for (i=0; i<array.length; i++) {
    val = val + array[i];
    if (i < (array.length-1)) val = val+str;
    }
  return val;
}
//-->
