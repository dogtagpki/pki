package com.netscape.pkisilent.http;

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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedHashSet;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HTMLDocument {
    // Indicates whether this HTML document has been parsed.
    boolean parsed;

    // A list of URLs of files that should be retrieved along with the main
    // contents of the document.  This may include any images contained in the
    // document, and possibly any external stylesheets.
    LinkedHashSet<String> associatedFiles;

    // A list of URLs of frames that are contained in the document.
    LinkedHashSet<String> documentFrames;

    // A list of URLs of links that are contained in the document.
    LinkedHashSet<String> documentLinks;

    // A list of URLs of images that are contained in the document.
    LinkedHashSet<String> documentImages;

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
    private int lastElementEndPos;
    private int lastElementStartPos;
    private String lastURL;

    // constructor that helps to parse without url stuff
    public HTMLDocument(String htmlData) {
        this.documentURL = null;
        this.htmlData = htmlData;
        lowerData = htmlData.toLowerCase();
        associatedFiles = null;
        documentLinks = null;
        documentImages = null;
        textData = null;
        parsed = false;

        // Create the regex patterns that we will use for extracting URIs from tags.
        hrefPattern = Pattern.compile(".*?[hH][rR][eE][fF][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);
        srcPattern = Pattern.compile(".*?[sS][rR][cC][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);
    }

    /**
     * Creates a new HTML document using the provided data.
     *
     * @param documentURL The URL for this document.
     * @param htmlData The actual data contained in the HTML document.
     */
    public HTMLDocument(String documentURL, String htmlData)
            throws MalformedURLException {
        this.documentURL = documentURL;
        this.htmlData = htmlData;
        lowerData = htmlData.toLowerCase();
        associatedFiles = null;
        documentLinks = null;
        documentImages = null;
        textData = null;
        parsed = false;

        // Create the regex patterns that we will use for extracting URIs from tags.
        hrefPattern = Pattern.compile(".*?[hH][rR][eE][fF][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);
        srcPattern = Pattern.compile(".*?[sS][rR][cC][\\s=\\\"\\']+" +
                                  "([^\\s\\\"\\'\\>]+).*", Pattern.DOTALL);

        URL url = new URL(documentURL);
        String urlPath = url.getPath();
        if ((urlPath == null) || (urlPath.length() == 0)) {
            baseURL = documentURL;
            protocolHostPort = documentURL;
        } else if (urlPath.equals("/")) {
            baseURL = documentURL;
            protocolHostPort = documentURL.substring(0, documentURL.length() - 1);
        } else if (urlPath.endsWith("/")) {
            baseURL = documentURL;

            int port = url.getPort();
            if (port > 0) {
                protocolHostPort = url.getProtocol() + "://" + url.getHost() + ":" +
                           port;
            } else {
                protocolHostPort = url.getProtocol() + "://" + url.getHost();
            }
        } else {
            int port = url.getPort();
            if (port > 0) {
                protocolHostPort = url.getProtocol() + "://" + url.getHost() + ":" +
                           port;
            } else {
                protocolHostPort = url.getProtocol() + "://" + url.getHost();
            }

            File urlFile = new File(urlPath);
            String parentDirectory = urlFile.getParent();
            if ((parentDirectory == null) || (parentDirectory.length() == 0)) {
                parentDirectory = "/";
            } else if (!parentDirectory.startsWith("/")) {
                parentDirectory = "/" + parentDirectory;
            }

            baseURL = protocolHostPort + parentDirectory;
        }

        if (!baseURL.endsWith("/")) {
            baseURL = baseURL + "/";
        }
    }

    /**
     * Actually parses the HTML document and extracts useful elements from it.
     *
     * @return <CODE>true</CODE> if the page could be parsed successfully, or <CODE>false</CODE> if not.
     */
    public boolean parse() {
        if (parsed) {
            return true;
        }

        try {
            associatedFiles = new LinkedHashSet<String>();
            documentFrames = new LinkedHashSet<String>();
            documentLinks = new LinkedHashSet<String>();
            documentImages = new LinkedHashSet<String>();
            textData = new StringBuffer();

            lastElementStartPos = 0;
            lastElementEndPos = -1;
            String element;
            while ((element = nextDocumentElement()) != null) {
                if (element.length() == 0) {
                    continue;
                }

                if (lastElementIsText) {
                    char lastChar;
                    if (textData.length() == 0) {
                        lastChar = ' ';
                    } else {
                        lastChar = textData.charAt(textData.length() - 1);
                    }
                    char firstChar = element.charAt(0);
                    if (!((lastChar == ' ') || (lastChar == '\t') ||
                            (lastChar == '\r') || (lastChar == '\n')) ||
                            (firstChar == ' ') || (firstChar == '\t') ||
                            (firstChar == '\r') || (firstChar == '\n')) {
                        textData.append(" ");
                    }

                    textData.append(element);
                } else if (lastElementIsImage) {
                    if (lastURL != null) {
                        documentImages.add(lastURL);
                        associatedFiles.add(lastURL);
                    }
                } else if (lastElementIsFrame) {
                    if (lastURL != null) {
                        documentFrames.add(lastURL);
                        associatedFiles.add(lastURL);
                    }
                } else if (lastElementIsLink) {
                    if (lastURL != null) {
                        documentLinks.add(lastURL);
                    }
                } else if (lastElementIsAssociatedFile) {
                    if (lastURL != null) {
                        associatedFiles.add(lastURL);
                    }
                } else if (lastElementIsChunk || lastElementIsComment) {
                    // Don't need to do anything with this.
                } else {
                    // Also don't need anything here.
                }
            }

            parsed = true;
        } catch (Exception e) {
            associatedFiles = null;
            documentLinks = null;
            documentImages = null;
            textData = null;
            parsed = false;
        }

        return parsed;
    }

    /**
     * Retrieves the next element from the HTML document. An HTML element can
     * include a string of plain text, a single HTML tag, or a larger chunk of
     * HTML including a start and end tag, all of which should be considered a
     * single element.
     */
    private String nextDocumentElement() {
        // If we're at the end of the HTML, then return null.
        if (lastElementEndPos >= htmlData.length()) {
            return null;
        }

        // Initialize the variables we will use for the search.
        lastElementStartPos = lastElementEndPos + 1;
        lastElementIsAssociatedFile = false;
        lastElementIsChunk = false;
        lastElementIsComment = false;
        lastElementIsFrame = false;
        lastElementIsImage = false;
        lastElementIsLink = false;
        lastElementIsText = false;
        lastURL = null;

        // Find the location of the next open angle bracket.  If there is none, then
        // the rest of the document must be plain text.
        int openPos = lowerData.indexOf('<', lastElementStartPos);
        if (openPos < 0) {
            lastElementEndPos = htmlData.length();
            lastElementIsText = true;
            return htmlData.substring(lastElementStartPos);
        }

        // If the location of the next open tag is not we started looking, then read
        // everything up to that tag as text.
        if (openPos > lastElementStartPos) {
            lastElementEndPos = openPos - 1;
            lastElementIsText = true;
            return htmlData.substring(lastElementStartPos, openPos);
        }

        // The start position is an open tag.  See if the tag is actually "<!--",
        // which indicates an HTML comment.  If that's the case, then find the
        // closing "-->".
        if (openPos == lowerData.indexOf("<!--", lastElementStartPos)) {
            int closePos = lowerData.indexOf("-->", openPos + 1);
            if (closePos < 0) {
                // This looks like an unterminated comment.  We can't do much else
                // here, so just stop parsing.
                return null;
            } else {
                lastElementEndPos = closePos + 2;
                lastElementIsComment = true;
                return htmlData.substring(lastElementStartPos, lastElementEndPos + 1);
            }
        }

        // Find the location of the next close angle bracket.  If there is none,
        // then we have an unmatched open tag.  What to do here?  I guess just treat
        // the rest of the document as text.
        int closePos = lowerData.indexOf('>', openPos + 1);
        if (closePos < 0) {
            lastElementEndPos = htmlData.length();
            lastElementIsText = true;
            return htmlData.substring(lastElementStartPos);
        }

        // Grab the contents of the tag in both normal and lowercase.
        String tag = htmlData.substring(openPos, closePos + 1);
        String strippedTag = htmlData.substring(openPos + 1, closePos).trim();
        StringTokenizer tokenizer = new StringTokenizer(strippedTag, " \t\r\n=\"'");
        lastElementEndPos = closePos;

        if (!tokenizer.hasMoreTokens()) {
            return tag;
        }

        String token = tokenizer.nextToken();
        String lowerToken = token.toLowerCase();

        if (lowerToken.equals("a") || lowerToken.equals("area")) {
            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("href")) {
                    Matcher matcher = hrefPattern.matcher(tag);
                    lastURL = uriToURL(matcher.replaceAll("$1"));
                    if (lastURL != null) {
                        lastElementIsLink = true;
                    }
                    break;
                }
            }
        } else if (lowerToken.equals("base")) {
            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("href")) {
                    try {
                        Matcher matcher = hrefPattern.matcher(tag);
                        String uri = matcher.replaceAll("$1");
                        if (!uri.endsWith("/")) {
                            uri = uri + "/";
                        }

                        baseURL = uri;
                    } catch (Exception e) {
                    }
                    break;
                }
            }
        } else if (lowerToken.equals("frame") || lowerToken.equals("iframe") ||
                lowerToken.equals("input")) {
            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("src")) {
                    try {
                        Matcher matcher = srcPattern.matcher(tag);
                        String uri = matcher.replaceAll("$1");
                        lastURL = uriToURL(uri);
                        if (lastURL != null) {
                            lastElementIsFrame = true;
                            lastElementIsAssociatedFile = true;
                        }
                    } catch (Exception e) {
                    }
                    break;
                }
            }
        } else if (lowerToken.equals("img")) {
            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("src")) {
                    try {
                        Matcher matcher = srcPattern.matcher(tag);
                        String uri = matcher.replaceAll("$1");
                        lastURL = uriToURL(uri);
                        if (lastURL != null) {
                            lastElementIsImage = true;
                        }
                    } catch (Exception e) {
                    }
                    break;
                }
            }
        } else if (lowerToken.equals("link")) {
            boolean isStyleSheet = false;

            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("href")) {
                    try {
                        Matcher matcher = hrefPattern.matcher(tag);
                        String uri = matcher.replaceAll("$1");
                        lastURL = uriToURL(uri);
                        if (lastURL != null) {
                            lastElementIsLink = true;
                        }
                    } catch (Exception e) {
                    }
                    break;
                } else if (token.equalsIgnoreCase("rel")) {
                    if (tokenizer.hasMoreTokens()) {
                        String relType = tokenizer.nextToken();
                        if (relType.equalsIgnoreCase("stylesheet")) {
                            isStyleSheet = true;
                        }
                    }
                }
            }

            if (lastURL != null) {
                if (isStyleSheet) {
                    lastElementIsAssociatedFile = true;
                } else {
                    lastElementIsLink = true;
                }
            }
        } else if (lowerToken.equals("script")) {
            while (tokenizer.hasMoreTokens()) {
                token = tokenizer.nextToken();
                if (token.equalsIgnoreCase("src")) {
                    try {
                        Matcher matcher = srcPattern.matcher(tag);
                        String uri = matcher.replaceAll("$1");
                        lastURL = uriToURL(uri);
                    } catch (Exception e) {
                    }
                    break;
                }
            }

            if (lastURL == null) {
                int endScriptPos = lowerData.indexOf("</script>", lastElementEndPos + 1);
                if (endScriptPos > 0) {
                    lastElementEndPos = endScriptPos + 8;
                    tag = htmlData.substring(lastElementStartPos, lastElementEndPos + 1);
                    lastElementIsChunk = true;
                }
            } else {
                lastElementIsAssociatedFile = true;
            }
        }

        return tag;
    }

    /**
     * Converts the provided URI to a URL. The provided URI may be a URL already,
     * or it may also be an absolute path on the server or a path relative to the
     * base URL.
     *
     * @param uri The URI to convert to a URL.
     *
     * @return The URL based on the provided URI.
     */
    private String uriToURL(String uri) {
        String url = null;

        if (uri.indexOf("://") > 0) {
            if (uri.startsWith("http")) {
                url = uri;
            }
        } else if (uri.startsWith("/")) {
            url = protocolHostPort + uri;
        } else {
            url = baseURL + uri;
        }

        return url;
    }

    /**
     * Retrieves the URL of this HTML document.
     *
     * @return The URL of this HTML document.
     */
    public String getDocumentURL() {
        return documentURL;
    }

    /**
     * Retrieves the original HTML data used to create this document.
     *
     * @return The orginal HTML data used to create this document.
     */
    public String getHTMLData() {
        return htmlData;
    }

    /**
     * Retrieves the contents of the HTML document with all tags removed.
     *
     * @return The contents of the HTML document with all tags removed, or <CODE>null</CODE> if a problem occurs while
     *         trying to parse the
     *         HTML.
     */
    public String getTextData() {
        if (!parsed) {
            if (!parse()) {
                return null;
            }
        }

        return textData.toString();
    }

    /**
     * Retrieves an array containing a set of URLs parsed from the HTML document
     * that reference files that would normally be downloaded as part of
     * retrieving a page in a browser. This includes images and external style
     * sheets.
     *
     * @return An array containing a set of URLs to files associated with the
     *         HTML document, or <CODE>null</CODE> if a problem occurs while
     *         trying to parse the HTML.
     */
    public String[] getAssociatedFiles() {
        if (!parsed) {
            if (!parse()) {
                return null;
            }
        }

        String[] urlArray = new String[associatedFiles.size()];
        associatedFiles.toArray(urlArray);
        return urlArray;
    }

    /**
     * Retrieves an array containing a set of URLs parsed from the HTML document
     * that are in the form of links to other content.
     *
     * @return An array containing a set of URLs parsed from the HTML document
     *         that are in the form of links to other content, or <CODE>null</CODE> if a problem occurs while trying to
     *         parse the
     *         HTML.
     */
    public String[] getDocumentLinks() {
        if (!parsed) {
            if (!parse()) {
                return null;
            }
        }

        String[] urlArray = new String[documentLinks.size()];
        documentLinks.toArray(urlArray);
        return urlArray;
    }

    /**
     * Retrieves an array containing a set of URLs parsed from the HTML document
     * that reference images used in the document.
     *
     * @return An array containing a set of URLs parsed from the HTML document
     *         that reference images used in the document.
     */
    public String[] getDocumentImages() {
        if (!parsed) {
            if (!parse()) {
                return null;
            }
        }

        String[] urlArray = new String[documentImages.size()];
        documentImages.toArray(urlArray);
        return urlArray;
    }

    /**
     * Retrieves an array containing a set of URLs parsed from the HTML document
     * that reference frames used in the document.
     *
     * @return An array containing a set of URLs parsed from the HTML document
     *         that reference frames used in the document.
     */
    public String[] getDocumentFrames() {
        if (!parsed) {
            if (!parse()) {
                return null;
            }
        }

        String[] urlArray = new String[documentFrames.size()];
        documentFrames.toArray(urlArray);
        return urlArray;
    }
}
