# -*- coding: utf-8 -*-

import re
from burp import IBurpExtender, IHttpListener, IScannerCheck, IExtensionStateListener, IContextMenuFactory, \
    IScanIssue, IBurpExtenderCallbacks, IExtensionHelpers, IHttpRequestResponse, IRequestInfo, IResponseInfo, \
    IScannerInsertionPoint, IContextMenuInvocation
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList
from javax.swing import JMenuItem, JOptionPane


class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener, IScannerCheck, IContextMenuFactory):
    EXTENSION_NAME = "JSpector"
    EXTENSION_VERSION = "2.4.8"
    EXPORT_TARGETS = {"URLs", "endpoints", "results"}
    ONLY_EXPORT_ALREADY_SCANNED_URLS = False
    ONLY_IN_SCOPE_EXPORT = False
    ONLY_IN_SCOPE_PASSIVE_SCAN = True
    ONLY_IN_SCOPE_PROXY = True
    PATTERN_ENDPOINT_1 = re.compile(r'(?:(?<=["\'])/(?:[^/"\']+/?)+(?=["\']))')
    PATTERN_ENDPOINT_2 = re.compile(r'http\.(?:post|get|put|delete|patch)\(["\']((?:[^/"\']+/?)+)["\']')
    PATTERN_ENDPOINT_3 = re.compile(r'httpClient\.(?:post|get|put|delete|patch)\(this\.configuration\.basePath'
                                    r'\+["\']/(?:[^/"\']+/?)+["\']')
    PATTERN_EXCLUSION = re.compile(r'http://www\.w3\.org')
    PATTERN_URL_1 = re.compile(r'(?:http|https|ftp|ftps|sftp|file|tftp|telnet|gopher|ldap|ssh)://[^\s"<>]+')
    PATTERN_URL_2 = re.compile('^(?:http|https|ftp|ftps|sftp|file|tftp|telnet|gopher|ldap|ssh)://')

    def __init__(self):
        self._callbacks = None
        self._helpers = None
        self._scanned_js_files = set()

    # *** IBurpExtender interface methods implementation *** #

    def registerExtenderCallbacks(self, callbacks):
        """ This method is invoked when the extension is loaded. It registers an IBurpExtenderCallbacks interface,
        providing methods that may be invoked by the extension to perform various actions.

        :param IBurpExtenderCallbacks callbacks: IBurpExtenderCallbacks object
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(BurpExtender.EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        self._callbacks.printOutput(
            "JSpector {} extension loaded successfully.\nWarning: the size of the output console content is limited, "
            "we recommend that you save your results in a file.".format(BurpExtender.EXTENSION_VERSION))

    # *** IExtensionStateListener interface methods implementation *** #

    def extensionUnloaded(self):
        """ This method is called when the extension is unloaded. """
        self._callbacks.printOutput("{} extension unloaded.".format(BurpExtender.EXTENSION_NAME))

    # *** IHttpListener interface methods implementation *** #

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        """ This method is invoked when an HTTP request is about to be issued, and when an HTTP response has
        been received.

        :param int tool_flag: A flag indicating the Burp tool that issued the request. See IBurpExtenderCallbacks
        :param bool message_is_request: Flags whether the method is being invoked for a request or response
        :param IHttpRequestResponse message_info: Details of the request / response to be processed
        """
        url = self._helpers.analyzeRequest(message_info).getUrl()
        js_url = url.toString()

        # Ignore tools other than PROXY, requests, out-of-scope responses, and already scanned URLs
        if tool_flag != self._callbacks.TOOL_PROXY \
                or message_is_request \
                or (BurpExtender.ONLY_IN_SCOPE_PROXY and not self._callbacks.isInScope(url)) \
                or js_url in self._scanned_js_files:
            return None

        response = message_info.getResponse()
        if response:
            response_info = self._helpers.analyzeResponse(response)
            # Process only javascript responses
            if BurpExtender.is_javascript_response(js_url, response_info):
                # Tag URL as scanned
                self._scanned_js_files.add(js_url)
                # Search URLs and endpoints in response body and create issue
                body = response[response_info.getBodyOffset():]
                urls = BurpExtender.extract_urls_from_js(body)
                if urls:
                    self._callbacks.addScanIssue(self._create_issue_and_output_results(message_info, urls))

    # *** IScannerCheck interface methods implementation *** #

    def doPassiveScan(self, base_request_response):
        """ The Scanner invokes this method for each base request / response that is passively scanned.

        Note: Extensions should only analyze the HTTP messages provided during passive scanning, and should not make
        any new HTTP requests of their own.

        :param IHttpRequestResponse base_request_response: Base HTTP req / resp that should be passively scanned
        :return: A list of IScanIssue objects, or null if no issues are identified
        :rtype: list[IScanIssue]
        """
        issues = []
        url = self._helpers.analyzeRequest(base_request_response).getUrl()
        js_url = url.toString()
        response = base_request_response.getResponse()

        # Ignore out-of-scope responses, and already scanned URLs
        if (BurpExtender.ONLY_IN_SCOPE_PASSIVE_SCAN and not self._callbacks.isInScope(url)) \
                or js_url in self._scanned_js_files:
            return issues

        if response:
            response_info = self._helpers.analyzeResponse(response)
            # Process only javascript responses
            if BurpExtender.is_javascript_response(js_url, response_info):
                # Tag js_url as scanned
                self._scanned_js_files.add(js_url)
                # Search URLs and endpoints in response body and create issue
                body = response[response_info.getBodyOffset():]
                urls = BurpExtender.extract_urls_from_js(body)
                if urls:
                    issues.append(self._create_issue_and_output_results(base_request_response, urls))
                else:
                    self._callbacks.printOutput("\nNo valid results for: {}".format(js_url))

        return issues

    def doActiveScan(self, base_request_response, insertion_point):
        """ The Scanner invokes this method for each insertion point that is actively scanned. Extensions may issue
        HTTP requests as required to carry out active scanning, and should use the IScannerInsertionPoint object
        provided to build scan requests for particular payloads.

        Note: Scan checks should submit raw non-encoded payloads to insertion points, and the insertion point has
        responsibility for performing any data encoding that is necessary given the nature and location of the
        insertion point.

        :param IHttpRequestResponse base_request_response: The base HTTP req / resp that should be actively scanned
        :param IScannerInsertionPoint insertion_point: An IScannerInsertionPoint object
        :return: A list of IScanIssue objects, or null if no issues are identified
        :rtype: list[IScanIssue]
        """
        pass

    def consolidateDuplicateIssues(self, existing_issue, new_issue):
        """ The Scanner invokes this method when the custom Scanner check has reported multiple issues for the same
        URL path. This can arise either because there are multiple distinct vulnerabilities, or because the same
        (or a similar) request has been scanned more than once. The custom check should determine whether the issues
        are duplicates. In most cases, where a check uses distinct issue names or descriptions for distinct issues,
        the consolidation process will simply be a matter of comparing these features for the two issues.

        :param IScanIssue existing_issue: An issue that was previously reported by this Scanner check
        :param IScanIssue new_issue:  An issue at the same URL path that has been newly reported by this Scanner check
        :return: -1 to report the existing issue only, 0 to report both issues, and 1 to report the new issue only
        :rtype: int
        """
        if existing_issue.getIssueDetail() == new_issue.getIssueDetail():
            return -1
        else:
            return 0

    # *** IContextMenuFactory interface methods implementation *** #

    def createMenuItems(self, invocation):
        """ This method will be called by Burp when the user invokes a context menu anywhere within Burp. The
        factory can then provide any custom context menu items that should be displayed in the context menu, based
        on the details of the menu invocation.

        :param IContextMenuInvocation invocation: An object that implements the IMessageEditorTabFactory interface
        :return: A list of custom menu items that should be displayed.
        :rtype: list[JMenuItem]
        """
        menu_items = ArrayList()

        menu_item1 = JMenuItem("Export URLs to clipboard", None,
                               actionPerformed=lambda x, inv=invocation: self._export_to_clipboard(inv, "URLs"))
        menu_items.add(menu_item1)

        menu_item2 = JMenuItem("Export endpoints to clipboard", None,
                               actionPerformed=lambda x, inv=invocation: self._export_to_clipboard(inv, "endpoints"))
        menu_items.add(menu_item2)

        menu_item3 = JMenuItem("Export all results to clipboard", None,
                               actionPerformed=lambda x, inv=invocation: self._export_to_clipboard(inv, "results"))
        menu_items.add(menu_item3)

        return menu_items

    # *** Protected methods *** #

    def _create_issue_and_output_results(self, message_info, urls):
        """ Create a new Burp scanner issue and send results to the extension output.

        :param IHttpRequestResponse message_info: Base HTTP request / response at the origin of the issue
        :param set[str] urls: Found URLs and endpoints (BurpExtender.extract_urls_from_js() results)
        :return: Created IScanIssue object, required for IScannerCheck.doPassiveScan
        :rtype: IScanIssue
        """
        issue = JSURLsIssue(self._helpers, message_info, urls)
        js_full_url = self._helpers.analyzeRequest(message_info).getUrl().toString()
        self._output_results(urls, js_full_url)

        return issue

    def _export_to_clipboard(self, invocation, export_target):
        """ Method called when clicking on extension JMenuItem to export results to the clipboard.

        :param IContextMenuInvocation invocation: IContextMenuFactory.createMenuItems invocation argument
        :param str export_target: Target to export. Refers to BurpExtender.EXPORT_TARGETS
        """
        all_results = ""
        messages = invocation.getSelectedMessages()

        if messages is None:
            JOptionPane.showMessageDialog(None, "No JS file selected")
            return None

        for message in messages:
            url = self._helpers.analyzeRequest(message).getUrl()
            js_url = url.toString()
            # Skip message if out-of-scope or not already scanned URL
            if (BurpExtender.ONLY_IN_SCOPE_EXPORT and not self._callbacks.isInScope(url)) \
                    or (BurpExtender.ONLY_EXPORT_ALREADY_SCANNED_URLS and js_url not in self._scanned_js_files):
                self._callbacks.printOutput(
                    "Clipboard export - Skip '{}' url (OOS or not already scanned)".format(js_url))
                continue

            response = message.getResponse()
            if response:
                response_info = self._helpers.analyzeResponse(response)
                # Process only javascript responses
                if BurpExtender.is_javascript_response(js_url, response_info):
                    # Search URLs and endpoints in response body and them to all_results
                    body = response[response_info.getBodyOffset():]
                    urls = BurpExtender.extract_urls_from_js(body)
                    if urls:
                        all_results += BurpExtender.export_results(urls, export_target)

        # Copy all results to clipboard
        BurpExtender.copy_to_clipboard(all_results, export_target)

    def _output_results(self, urls, js_full_url):
        """ Send all results to the extension output.

        :param set[str] urls: Found URLs and endpoints (BurpExtender.extract_urls_from_js() results)
        :param str js_full_url: Request URL
        """
        urls_list, endpoints_list = BurpExtender.sort_urls_endpoints(urls)

        self._callbacks.printOutput("\n{} results for {}:".format(BurpExtender.EXTENSION_NAME, js_full_url))
        self._callbacks.printOutput("-----------------")
        if urls_list:
            self._callbacks.printOutput(
                "URLs found ({}):\n-----------------\n{}".format(len(urls_list), '\n'.join(urls_list)))
        else:
            self._callbacks.printOutput("No URLs found.\n-----------------")

        if endpoints_list:
            self._callbacks.printOutput("\nEndpoints found ({}):".format(len(endpoints_list)))
            self._callbacks.printOutput("-----------------\n{}".format('\n'.join(endpoints_list)))
        else:
            self._callbacks.printOutput("No endpoints found.")

        self._callbacks.printOutput("-----------------")

    # *** Public static methods *** #

    @staticmethod
    def copy_to_clipboard(source, source_type):
        """ Copy all results to clipboard.

        :param str source: Text to export
        :param str source_type: Source type, to adapt message in showMessageDialog. See BurpExtender.EXPORT_TARGETS
        """
        if source:
            src_lines_number = len(source.split('\n')) - 1
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(source), None)
            JOptionPane.showMessageDialog(None, "{} {} exported to clipboard".format(src_lines_number, source_type))
        else:
            JOptionPane.showMessageDialog(None, "No {} found to export".format(source_type))

    @staticmethod
    def export_results(urls, export_target):
        if export_target not in BurpExtender.EXPORT_TARGETS:
            raise ValueError(
                "Unknown export target '{}'. Must be in {}".format(export_target, BurpExtender.EXPORT_TARGETS))

        urls_list, endpoints_list = BurpExtender.sort_urls_endpoints(urls)
        formatted_results = ""

        if export_target in ["URLs", "results"]:
            for url in urls_list:
                formatted_results += url + "\n"

        if export_target in ["endpoints", "results"]:
            for endpoint in endpoints_list:
                formatted_results += endpoint + "\n"

        return formatted_results

    @staticmethod
    def extract_urls_from_js(js_code):
        """ Find all URLs and endpoints that match the defined regular expressions in the JavaScript source code.

        :param str js_code: JavaScript source code
        :return: Found URLs and endpoints
        :rtype: set[str]
        """
        urls = set(BurpExtender.PATTERN_URL_1.findall(js_code))
        endpoints1 = set(BurpExtender.PATTERN_ENDPOINT_1.findall(js_code))
        endpoints2 = set(BurpExtender.PATTERN_ENDPOINT_2.findall(js_code))
        endpoints3 = set(BurpExtender.PATTERN_ENDPOINT_3.findall(js_code))

        urls = set(url for url in urls if not BurpExtender.PATTERN_EXCLUSION.search(url))

        return urls.union(endpoints1, endpoints2, endpoints3)

    @staticmethod
    def is_javascript_response(url, response_info):
        """ Check the response Content-Type or the url extension to determine if the response may contain
        JavasScript source code..

        :param str url: Request URL
        :param IResponseInfo response_info: HTTP Response (IExtensionHelpers.analyzeResponse)
        :return: True if response Content-Type include 'javascript' or URL ends with '.js' else False
        :rtype: bool
        """
        headers = response_info.getHeaders()
        content_type = next(
            (header.split(':', 1)[1].strip() for header in headers if header.lower().startswith('content-type:')), None)

        return 'javascript' in content_type.lower() or url.lower().endswith('.js')

    @staticmethod
    def sort_urls_endpoints(urls):
        """ Differentiates in an unsorted set from the extract_urls_from_js method the URLs and the endpoints
        and returns them sorted in two distinct lists.

        :param set[str] urls: Set of URLs and endpoints to sort (BurpExtender.extract_urls_from_js() results)
        :return: Tuple of sorted URLS and sorted endpoints
        :rtype: tuple[list, list]
        """
        urls_list = []
        endpoints_list = []

        for url in urls:
            if BurpExtender.PATTERN_URL_2.match(url):
                urls_list.append(url)
            else:
                endpoints_list.append(url)

        urls_list.sort()
        endpoints_list.sort()

        return urls_list, endpoints_list


class JSURLsIssue(IScanIssue):

    def __init__(self, helpers, message_info, urls):
        """ JSURLsIssue init method.

        :param IExtensionHelpers helpers: Come from BurpExtender
        :param IHttpRequestResponse message_info: Base HTTP request / response at the origin of the issue
        :param set[str] urls: Found URLs and endpoints (BurpExtender.extract_urls_from_js() results)
        """
        self._helpers = helpers
        self._httpService = message_info.getHttpService()
        self._url = self._helpers.analyzeRequest(message_info).getUrl()
        self._urls = urls

    # IScanIssue interface methods implementation #

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "{} results".format(BurpExtender.EXTENSION_NAME)

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "The following URLs were found in a JavaScript file. This information may be useful for further testing."

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        urls_list, endpoints_list = BurpExtender.sort_urls_endpoints(self._urls)

        details = self.build_list("URLs found", urls_list)
        details += self.build_list("Endpoints found", endpoints_list)

        return details

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return []

    def getHttpService(self):
        return self._httpService

    # *** Public static methods *** #

    @staticmethod
    def build_list(title, items):
        if not items:
            return ""

        details = "<b>{title} ({num_items}):</b>".format(title=title, num_items=len(items))
        details += "<ul>"

        for item in items:
            details += "<li>{item}</li>".format(item=item)

        details += "</ul>"

        return details
