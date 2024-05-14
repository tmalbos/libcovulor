from libcovulor import Finding
import os
from pymongo import MongoClient

finding = Finding(mongodb_server=os.getenv('MONGODB_SERVER', 'mongodb://localhost'))
# client = MongoClient(os.getenv('MONGODB_SERVER', 'mongodb://localhost'), 27017)
# finding = Finding(client=client)

data_create = {
    "client_id": "65f079f3ef898e6a6bb37e5b",
    "repository_id": "609e80d0a8024e00011e6f58",
    "title": "Open Redirect - nusoap.php: 3729",
    "description": "##Category: Open Redirect\n###Abstract:\nThe file nusoap.php passes unvalidated data to an HTTP redirect function on line 3729. Allowing unvalidated input to control the URL used in a redirect can aid phishing attacks.\n###Snippet:\n**File: nusoap.php: 3729**\n```\nn/a\n```\n##Source:\nThis snippet provides more context on the execution path that leads to this finding. \n####Snippet:\n**File: nusoap.php: 4442**\n```\n\t\t\t} elseif (isset($HTTP_SERVER_VARS)) {\n\t\t\t\t$SERVER_NAME = $HTTP_SERVER_VARS['SERVER_NAME'];\n\t\t\t\t$SCRIPT_NAME = isset($HTTP_SERVER_VARS['PHP_SELF']) ? $HTTP_SERVER_VARS['PHP_SELF'] : $HTTP_SERVER_VARS['SCRIPT_NAME'];\n\t\t\t\t$HTTPS = isset($HTTP_SERVER_VARS['HTTPS']) ? $HTTP_SERVER_VARS['HTTPS'] : 'off';\n\t\t\t} else {\n```\n##Explanation:\n Redirects allow web applications to direct users to different pages within the same application or to external sites. Applications utilize redirects to aid in site navigation and, in some cases, to track how users exit the site. Open redirect vulnerabilities occur when a web application redirects clients to any arbitrary URL that can be controlled by an attacker. \n\nAttackers can utilize open redirects to trick users into visiting a URL to a trusted site and redirecting them to a malicious site. By encoding the URL, an attacker can make it more difficult for end-users to notice the malicious destination of the redirect, even when it is passed as a URL parameter to the trusted site. Open redirects are often abused as part of phishing scams to harvest sensitive end-user data.\n\n\n\n\nExample 1: The following PHP code instructs the user's browser to open a URL parsed from the dest request parameter when a user clicks the link. \n\n\n    <%\n        ...\n        $strDest = $_GET[\"dest\"];\n        header(\"Location: \" . $strDest);\n        ...\n    %>\n\n\nIf a victim received an email instructing the user to follow a link to \"http://trusted.example.com/ecommerce/redirect.php?dest=www.wilyhacker.com\", the user would likely click on the link believing they would be transferred to the trusted site. However, when the user clicks the link, the code above will redirect the browser to \"http://www.wilyhacker.com\". \n\nMany users have been educated to always inspect URLs they receive in emails to make sure the link specifies a trusted site they know. However, if the attacker Hex encoded the destination url as follows:\n \"http://trusted.example.com/ecommerce/redirect.php?dest=%77%69%6C%79%68%61%63%6B%65%72%2E%63%6F%6D\"\n\nthen even a savvy end-user may be fooled into following the link.",
    "date": "2024-02-27T11:40:00.000Z",
    "status": "",
    "scan_id": "65f1f58823c44b92e81a7d28",
    "is_false_positive": False,
    "is_mitigated_externally": False,
    "duplicate": False,
    "duplicate_finding_id": "",
    "cwe": ["601"],
    "cvssv4_vector": "",
    "cvssv4_score": "",
    "cvssv3_vector": "",
    "cvssv3_score": "",
    "estimated_epss": 0,
    "effort_for_fixing": "",
    "scanner_id": "EC64C37D83AAB5B4F676E2ED855AB54C",
    "scanner_report": "Open Redirect\n            Input Validation and Representation\n            The file nusoap.php passes unvalidated data to an HTTP redirect function on line 3729. Allowing unvalidated input to control the URL used in a redirect can aid phishing attacks.\n            ",
    "scanner_report_code": "              if (strpos($this->externalWSDLURL, \"http://\") !== false) { // assume URL\n\t\t\t\t$this->debug(\"In service, re-direct for WSDL\");\n\t\t\t\theader('Location: '.$this->externalWSDLURL);\n              } else { // assume file\n\t\t\t\t$this->debug(\"In service, use file passthru for WSDL\");",
    "scanner_weakness": "",
    "scanner_confidence": "",
    "scanner_severity": "Critical",
    "scanner_severity_numerical": "",
    "scanner_mitigation": "###Recommendation:\n Unvalidated user input should not be allowed to control the destination URL in a redirect. Instead, a level of indirection should be introduced: create a list of legitimate URLs that users are allowed to specify and only allow users to select from the list. With this approach, input provided by users is never used directly to specify a URL for redirects.\n\nExample 2: The following code references an array populated with valid URLs. The link the user clicks passes in the array index that corresponds to the desired URL.\n\n\n    <%\n        ...\n            $strDest = intval($_GET[\"dest\"]);\n            if(($strDest >= 0) && ($strDest <= count ($strURLArray) - 1 ))\n            {\n                $strFinalURL = $strURLArray[strDest];\n                header(\"Location: \" . $strFinalURL);\n            }\n        ...\n    %>\n\n\nIn some situations this approach is impractical because the set of legitimate URLs is too large or too hard to keep track of. In such cases, use a similar approach to restrict the domains that users can be redirected to, which can at least prevent attackers from sending users to malicious external sites.\n###Tips:\n 1. A number of modern web frameworks provide mechanisms for performing validation of user input. Struts and Struts 2 are among them. To highlight the unvalidated sources of input, the HP Fortify Secure Coding Rulepacks dynamically re-prioritize the issues reported by HP Fortify Static Code Analyzer by lowering their probability of exploit and providing pointers to the supporting evidence whenever the framework validation mechanism is in use. We refer to this feature as Context-Sensitive Ranking. To further assist the HP Fortify user with the auditing process, the Fortify Security Research Group makes available the Data Validation project template that groups the issues into folders based on the validation mechanism applied to their source of input.\n\n2. Due to the dynamic nature of PHP, you may see a large number of findings in PHP library files.  Consider using a filter file to hide specific findings from view.  For instructions on creating a filter file, see Advanced Options in the HP Fortify Static Code Analyzer User Guide.",
    "sast_source_file_path": "",
    "sast_source_object": "",
    "sast_source_line": "",
    "sast_sink_object": "",
    "impact": "",
    "file_path": "_japp/plugin/nusoap/nusoap.php",
    "original_line": 3729,
    "actual_line": 3729,
    "review_requested_by_id": "",
    "processing_status": "uploaded",
    "type": "code_weakness",
    "prioritization_value": 0,
    "tool": "fortify"
}


print("---------------------- Finding create")
id = finding.create_finding(data_create)
print(id)
print("---------------------- Finding List")
print(finding.get_findings_by_client_id('65f079f3ef898e6a6bb37e5b', {"pagination": {
      "page_size": 1, "page": 1, "paginate": False}, "filters": {"tool": "fortify"}, "sort": {"order": 1, "field": "date"}}))

print("---------------------- Finding update")
print(finding.update_finding_by_id_and_client_id(
    {'is_false_positive': True}, id, '65f079f3ef898e6a6bb37e5b'))

print("---------------------- Finding by id and client id")
print(finding.get_finding_by_id_and_client_id(
    {'finding_id': id, 'client_id': '65f079f3ef898e6a6bb37e5b'}))

print("---------------------- Finding delete")
print(finding.delete_finding_by_id_and_client_id(
    id, '65f079f3ef898e6a6bb37e5b'))
finding.close_connection()
