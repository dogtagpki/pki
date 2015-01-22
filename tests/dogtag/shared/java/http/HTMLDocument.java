import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;



public class HTMLDocument
{
  // Indicates whether this HTML document has been parsed.
     boolean parsed;
  
  // A list of URLs of files that should be retrieved along with the main
  // contents of the document.  This may include any images contained in the
  // document, and possibly any external stylesheets.
  LinkedHashSet associatedFiles;
  
  // A list of URLs of frames that are contained in the document.
  LinkedHashSet documentFrames;
  
  // A list of URLs of links that are contained in the document.
  LinkedHashSet documentLinks;
  
  // A list of URLs of images that are contained in the document.
  LinkedHashSet documentImages;
  
  // A regular expression pattern that can be used to extract a URI from an HREF
  // tag.
  Pattern hrefPattern;
  
  // A regular expression pattern that can be used to extract a URI from a SRC
  // tag.
  Pattern srcPattern;
  
  // The base URL for relative links in this document.
  String baseURL;
  
  // The URL that may be used to access this document.
  String documentURL;
  
  // The actual contents of the page.
  String htmlData;
  
  // The contents of the page converted to lowercase for easier matching.
  String lowerData;
  
  // The URL for this document with only protocol, host, and port (i.e., no
  // file).
  String protocolHostPort;
  
  // A string buffer containing the contents of the page with tags removed.
  StringBuffer textData;
  
  
  // A set of private variables used for internal processing.
  private boolean lastElementIsAssociatedFile;
  private boolean lastElementIsChunk;
  private boolean lastElementIsComment;
  private boolean lastElementIsFrame;
  private boolean lastElementIsImage;
  private boolean lastElementIsLink;
  private boolean lastElementIsText;
  private int     lastElementEndPos;
  private int     lastElementStartPos;
  private String  lastURL;

	// constructor that helps to parse without url stuff
	public HTMLDocument(String htmlData) 
  {
    this.documentURL = null;
    this.htmlData    = htmlData;
    lowerData        = htmlData.toLowerCase();
    associatedFiles  = null;
    documentLinks    = null;
    documentImages   = null;
    textData         = null;
    parsed           = false;


    // Create the regex patterns that we will use for extracting URIs from tags.
    hrefPattern = Pattern.compile(".*?[hH][rR][eE][fF][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);
    srcPattern  = Pattern.compile(".*?[sS][rR][cC][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);
  }
}
