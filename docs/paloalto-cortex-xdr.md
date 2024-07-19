## About the connector
Cortex XDR applies machine learning at cloud scale to rich network, endpoint, and cloud data, so you can quickly find and stop targeted attacks, insider abuse, and compromised endpoints.
<p>This document provides information about the Palo Alto Cortex XDR Connector, which facilitates automated interactions, with a Palo Alto Cortex XDR server using FortiSOAR&trade; playbooks. Add the Palo Alto Cortex XDR Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Palo Alto Cortex XDR.</p>

### Version information

Connector Version: 1.2.0


Authored By: Fortinet

Certified: No
## Release Notes for version 1.2.0
Following enhancements have been made to the Palo Alto Cortex XDR Connector in version 1.2.0:
<ul>
<li>Added a new operation named "Get query result by query ID".</li>
<li>Added a new operation named "XQL Query". </li>

<li>Fix the issue of standard key and Advanced key of Palo Alto Cortex XDR connector.</li>
</ul>

## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-paloalto-cortex-xdr</pre>

## Prerequisites to configuring the connector
- You must have the credentials of Palo Alto Cortex XDR server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Palo Alto Cortex XDR server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Palo Alto Cortex XDR</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Specify the URL of the Palo Alto Cortex XDR server to which you will connect and perform the automated operations.
</td>
</tr><tr><td>Authentication Type</td><td>Select this authentication type as Standard Key or Advanced Key.
</td>
</tr><tr><td>API Key ID</td><td>Specify the ID of the API key configured for your account to access the Palo Alto Cortex XDR server to which you will connect and perform the automated operations.
</td>
</tr><tr><td>API Key</td><td>Specify the API key configured for your account to access the Palo Alto Cortex XDR server to which you will connect and perform the automated operations. Note: You require a "Standard" security level API key.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Fetch Incidents</td><td>Retrieves all incidents or specific incidents from Palo Alto Cortex XDR based on the input parameters specified.</td><td>fetch_incidents <br/>Investigation</td></tr>
<tr><td>Get Incident Details</td><td>Retrieves details, including alerts and key artifacts, for a specific incident from Palo Alto Cortex XDR based on the incident ID and other input parameters specified.</td><td>get_incident_details <br/>Investigation</td></tr>
<tr><td>Update Incident</td><td>Updates incident fields like severity, status, etc. of a specific incident in Palo Alto Cortex XDR based on the incident ID and other input parameters specified.</td><td>update_incident <br/>Investigation</td></tr>
<tr><td>Insert CEF Alerts</td><td>Uploads alerts in the CEF format from external alert sources to Palo Alto Cortex XDR based on the list of alerts specified. Note: After you have mapped the CEF alert fields to Cortex XDR fields, Cortex XDR displays the alerts in related incidents and views.</td><td>insert_cef_alerts <br/>Investigation</td></tr>
<tr><td>Insert Parsed Alerts</td><td>Uploads alerts in the Cortex XDR format from external alert sources to Palo Alto Cortex XDR based on the product, vendor, and other input parameters specified. Cortex XDR displays alerts that are parsed successfully in related incidents and views.</td><td>insert_parsed_alerts <br/>Investigation</td></tr>
<tr><td>Isolate Endpoints</td><td>Isolates one or more endpoints in a single request on Palo Alto Cortex XDR based on the endpoint ID and other input parameters specified.</td><td>isolate_endpoints <br/>Investigation</td></tr>
<tr><td>Unisolate Endpoints</td><td>Unisolates one or more endpoints in a single request on Palo Alto Cortex XDR based on the endpoint ID and other input parameters specified.</td><td>unisolate_endpoints <br/>Investigation</td></tr>
<tr><td>Get All Endpoints</td><td>Retrieves a list of all your endpoints from Palo Alto Cortex XDR.</td><td>get_all_endpoints <br/>Investigation</td></tr>
<tr><td>Get Endpoints</td><td>Retrieves a list of filtered endpoints from Palo Alto Cortex XDR based on the input parameters specified.</td><td>get_endpoints <br/>Investigation</td></tr>
<tr><td>Scan Endpoints</td><td>Runs a scan on all endpoints or specified endpoints on Palo Alto Cortex XDR based on the list of endpoint IDs and other input parameters specified.</td><td>scan_endpoints <br/>Investigation</td></tr>
<tr><td>Cancel Scan Endpoints</td><td>Cancels a scan on all endpoints or specified endpoints on Palo Alto Cortex XDR based on the list of endpoint IDs and other input parameters specified.</td><td>cancel_scan_endpoints <br/>Investigation</td></tr>
<tr><td>Delete Endpoints</td><td>Deletes the specified endpoints from the Palo Alto Cortex XDR based on the list of endpoint IDs specified. Note: You can delete up to 100 endpoints.</td><td>delete_endpoints <br/>Investigation</td></tr>
<tr><td>Get Policy</td><td>Retrieves the policy for a specific endpoint from Palo Alto Cortex XDR based on the endpoint ID specified.</td><td>get_policy <br/>Investigation</td></tr>
<tr><td>Get Device Violations</td><td>Retrieves a list of filtered device violations from Palo Alto Cortex XDR based on the input parameters specified.</td><td>get_device_violations <br/>Investigation</td></tr>
<tr><td>Get Distribution Version</td><td>Retrieves a list of all the agent versions that are used for creating a distribution list from Palo Alto Cortex XDR.</td><td>get_distribution_version <br/>Investigation</td></tr>
<tr><td>Create Distributions</td><td>Creates an installation package on Palo Alto Cortex XDR based on the distribution name and description, and the package type specified.</td><td>create_distributions <br/>Investigation</td></tr>
<tr><td>Get Distribution Status</td><td>Checks and retrieves the status of an installation package from Palo Alto Cortex XDR based on the distribution ID specified.</td><td>get_distribution_status <br/>Investigation</td></tr>
<tr><td>Get Distribution URL</td><td>Retrieves the distribution URL for downloading the installation package from Palo Alto Cortex XDR based on the distribution ID and package type specified.</td><td>get_distribution_url <br/>Investigation</td></tr>
<tr><td>Get Audit Management Logs</td><td>Retrieves audit management logs from Palo Alto Cortex XDR based on the input parameters specified.</td><td>get_audit_management_log <br/>Investigation</td></tr>
<tr><td>Get Audit Agent Report</td><td>Retrieves agent event reports from Palo Alto Cortex XDR based on the input parameters specified.</td><td>get_audit_agent_report <br/>Investigation</td></tr>
<tr><td>Blacklist Files</td><td>Blacklists the specified files that have not already been blacklisted on Palo Alto Cortex XDR based on the list of file hash values and other input parameters specified.</td><td>blacklist_files <br/>Investigation</td></tr>
<tr><td>Whitelist Files</td><td>Whitelists the specified files that have not already been whitelisted on Palo Alto Cortex XDR based on the list of file hash values and other input parameters specified.</td><td>whitelist_files <br/>Investigation</td></tr>
<tr><td>Quarantine Files</td><td>Quarantines files on specified endpoints on Palo Alto Cortex XDR based on the list of endpoint IDs, the file path, and the file hash specified.</td><td>quarantine_files <br/>Investigation</td></tr>
<tr><td>Get Quarantine Status</td><td>Retrieves the quarantine status for a specific file from Palo Alto Cortex XDR based on the endpoint ID, file path, and file hash specified.</td><td>get_quarantine_status <br/>Investigation</td></tr>
<tr><td>Restore File</td><td>Restores a quarantined file on a specified endpoint on Palo Alto Cortex XDR based on the endpoint ID, file hash, and other input parameters specified.</td><td>restore_file <br/>Investigation</td></tr>
<tr><td>Retrieve File</td><td>Retrieves a file from specific endpoints from Palo Alto Cortex XDR based on the list of endpoint IDs, file path, and other input parameters specified. Note: You can retrieve up to 20 files from a maximum of 100 endpoints.</td><td>retrieve_file <br/>Investigation</td></tr>
<tr><td>Retrieve File Details</td><td>Retrieves details for a specific file from Palo Alto Cortex XDR based on the action ID specified.</td><td>retrieve_file_details <br/>Investigation</td></tr>
<tr><td>Execute XQL Query</td><td>Execute xql query on Palo Alto Cortex XDR based on the Query and other parameters specified.</td><td>xql_query <br/>Investigation</td></tr>
<tr><td>Get Query Results By Query ID</td><td>Retrieve unique execution ID used to retrieve the results by the Get XQL Query Results API.</td><td>get_query_result_by_query_id <br/>Investigation</td></tr>
</tbody></table>

### operation: Fetch Incidents
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID List</td><td>(Optional) Specify the list of incident IDs that you want to retrieve from Palo Alto Cortex XDR. Each item in the list must be an incident ID. For example, ["1234","1235"]
</td></tr><tr><td>Created After</td><td>(Optional) Select the DateTime using which you want to filter the incidents retrieved by this operation to include only those incidents that were created at the time specified or the time later than the time specified.
</td></tr><tr><td>Created Before</td><td>(Optional) Select the DateTime using which you want to filter the incidents retrieved by this operation to include only those incidents that were created at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Modified After</td><td>(Optional) Select the DateTime using which you want to filter the incidents retrieved by this operation to include only those incidents that were modified at the time specified or the time later than the time specified.
</td></tr><tr><td>Modified Before</td><td>(Optional) Select the DateTime using which you want to filter the incidents retrieved by this operation to include only those incidents that were modified at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Alert Sources</td><td>(Optional) Specify the sources which detected the alert and whose associated incidents you want to retrieve from Palo Alto Cortex XDR. For example, ["XDR Agent"].
</td></tr><tr><td>Status</td><td>(Optional) Select the status using which you want to filter the incidents retrieved by this operation. You can choose from options such as New, Resolved Known Issue, Resolved Auto, etc. you can choose from New, Under Investigation, Resolved Threat Handled, Resolved Known Issue, Resolved Duplicate, Resolved True Positive, Resolved False Positive, Resolved Security Testing, Resolved Auto and Resolved Other
</td></tr><tr><td>Description</td><td>(Optional) Specify the description of the incident you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Search From</td><td>(Optional) Specify the integer representing the starting offset within the query result set from which you want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Search To</td><td>(Optional) Specify the integer representing the end offset within the result set after which you do not want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Sort by Field</td><td>(Optional) Select the field by which you want to sort the incidents retrieved by this operation. You can choose between creation_time or modification_time.
</td></tr><tr><td>Sort by Order</td><td>(Optional) Select this option to order the incidents retrieved by this operation. You can choose between asc (ascending) or desc (Descending).
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "total_count": "",
        "result_count": "",
        "incidents": [
            {
                "incident_id": "",
                "creation_time": "",
                "modification_time": "",
                "detection_time": "",
                "status": "",
                "severity": "",
                "description": "",
                "assigned_user_mail": "",
                "assigned_user_pretty_name": "",
                "alert_count": "",
                "low_severity_alert_count": "",
                "med_severity_alert_count": "",
                "high_severity_alert_count": "",
                "user_count": "",
                "host_count": "",
                "notes": "",
                "resolve_comment": "",
                "manual_severity": "",
                "manual_description": "",
                "xdr_url": "",
                "starred": "",
                "hosts": [],
                "users": [],
                "incident_sources": []
            }
        ]
    }
}</pre>
### operation: Get Incident Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident whose details (including related alerts and key artifacts) you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Alerts Limit</td><td>(Optional) Specify the maximum number of alerts related to the specified incident you want to retrieve from Palo Alto Cortex XDR. By default, this is set to '1000'.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "incident": {
            "incident_id": "",
            "creation_time": "",
            "modification_time": "",
            "detection_time": "",
            "status": "",
            "severity": "",
            "description": "",
            "assigned_user_mail": "",
            "assigned_user_pretty_name": "",
            "alert_count": "",
            "low_severity_alert_count": "",
            "med_severity_alert_count": "",
            "high_severity_alert_count": "",
            "user_count": "",
            "host_count": "",
            "notes": "",
            "resolve_comment": "",
            "manual_severity": "",
            "manual_description": "",
            "xdr_url": "",
            "starred": "",
            "hosts": [],
            "users": [],
            "alert_sources": []
        },
        "alerts": {
            "total_count": "",
            "data": [
                {
                    "alert_id": "",
                    "detection_timestamp": "",
                    "source": "",
                    "severity": "",
                    "name": "",
                    "category": "",
                    "action": "",
                    "action_pretty": "",
                    "endpoint_id": "",
                    "description": "",
                    "host_ip": "",
                    "host_name": "",
                    "user_name": "",
                    "event_type": "",
                    "actor_process_image_name": "",
                    "actor_process_command_line": "",
                    "fw_app_id": "",
                    "is_whitelisted": "",
                    "starred": ""
                }
            ]
        },
        "network_artifacts": {
            "total_count": "",
            "data": [
                {
                    "type": "",
                    "alert_count": "",
                    "is_manual": "",
                    "network_domain": "",
                    "network_remote_ip": "",
                    "network_remote_port": "",
                    "network_country": ""
                }
            ]
        },
        "file_artifacts": {
            "total_count": "",
            "data": [
                {
                    "type": "",
                    "alert_count": "",
                    "is_manual": "",
                    "is_malicious": "",
                    "is_process": "",
                    "file_name": "",
                    "file_sha256": "",
                    "file_signature_status": "",
                    "file_signature_vendor_name": "",
                    "file_wildfire_verdict": ""
                }
            ]
        }
    }
}</pre>
### operation: Update Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident whose details you want to update in Palo Alto Cortex XDR.
</td></tr><tr><td>Assigned User Mail</td><td>(Optional) Specify the email address of the assignee to whom you want to assign the specified incident in Palo Alto Cortex XDR.
</td></tr><tr><td>Assigned User Pretty Name</td><td>(Optional) Specify the full name of the assignee to whom you want to assign the specified incident in Palo Alto Cortex XDR.
</td></tr><tr><td>Manual Severity</td><td>(Optional) Select the severity level that you want to assign to the specified incident in Palo Alto Cortex XDR. You can choose from the following options: High, Medium, Low, Critical, or Informational.
</td></tr><tr><td>Status</td><td>(Optional) Select the status level that you want to assign to the specified incident in Palo Alto Cortex XDR. You can choose from the following options: New, Under Investigation, Resolved Threat Handled, Resolved Know Issue, Resolved Duplicate, Resolved False Positive, or Resolved Other. you can choose from New, Under Investigation, Resolved True Positive, Resolved Security Testing, Resolved Known Issue, Resolved Duplicate, Resolved False Positive and Resolved Other
</td></tr><tr><td>Comment</td><td>(Optional) Select this option if you want to include a comment that explains the updates made to the specified incident. If you select this option, then you must specify the following parameters: Comment Action: Specify the action that should be performed for the comments, i.e., enter 'add' to add the comment to the specified incident. Value: Add the comment that explains the updates made to the specified incident.
<br><strong>If you choose 'true'</strong><ul><li>Comment Action: Specify the action that should be performed for the comments, i.e., enter 'add' to add the comment to the specified incident.</li><li>Value: Add the comment that explains the updates made to the specified incident.</li></ul></td></tr><tr><td>Resolve Comment</td><td>(Optional) Add a descriptive comment that explains the updates made to the specified incident.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "message": "",
    "status": ""
}</pre>
### operation: Insert CEF Alerts
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alerts</td><td>Specify a comma-separated list of alerts in the CEF format that you want to add (upload) to Palo Alto Cortex XDR.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Insert Parsed Alerts
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Alert Name</td><td>Specify the string defining the name of the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Product</td><td>Specify the string value that defines the product related to the alert that you want to upload to Palo Alto Cortex XDR. For example, VPN & Firewall-1
</td></tr><tr><td>Vendor</td><td>Specify the string value that defines the vendor related to the alert that you want to upload to Palo Alto Cortex XDR. For example, Check Point
</td></tr><tr><td>Local Port</td><td>Specify the integer value for the source port related to the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Remote IP</td><td>Specify the string value of the destination IP address related to the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Remote Port</td><td>Specify the integer value for the destination port related to the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Local IP</td><td>(Optional) Specify the string value for the source IP address related to the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Event Timestamp</td><td>(Optional) Select the occurrence DateTime of the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Severity</td><td>(Optional) Select the severity of the alert that you want to upload to Palo Alto Cortex XDR. You can choose from the following options: Informational, High, Medium, Low, or Unknown.
</td></tr><tr><td>Alert Description</td><td>(Optional) Specify the string value that contains the description of the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr><tr><td>Action Status</td><td>(Optional) Specify the string value that defines the action status of the alert that you want to upload to Palo Alto Cortex XDR.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Isolate Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Isolate Endpoint</td><td>(Optional) Select whether you want to isolate one endpoint or multiple endpoints. If you select Isolate One Endpoint, then in the Endpoint ID field specify the ID of the endpoint you want to isolate on Palo Alto Cortex XDR. If you select Isolate More Than One Endpoint, then in the Endpoint ID List field specify a list of endpoint IDs you want to isolate on Palo Alto Cortex XDR.
<br><strong>If you choose 'Isolate One Endpoint'</strong><ul><li>Endpoint ID: If you select Isolate One Endpoint, then in the Endpoint ID field specify the ID of the endpoint you want to isolate on Palo Alto Cortex XDR.</li></ul><strong>If you choose 'Isolate More Than One Endpoint'</strong><ul><li>Endpoint ID List: If you select Isolate More Than One Endpoint, then in the Endpoint ID List field specify a list of endpoint IDs you want to isolate on Palo Alto Cortex XDR.</li></ul></td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident to include the Isolate Endpoints action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "action_id": []
    }
}</pre>
### operation: Unisolate Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Unisolate Endpoint</td><td>(Optional) Select whether you want to unisolate one endpoint or multiple endpoints. If you select Unisolate One Endpoint, then in the Endpoint ID field specify the ID of the endpoint you want to unisolate on Palo Alto Cortex XDR. If you select Unisolate More Than One Endpoint, then in the Endpoint ID List field specify a list of endpoint IDs you want to unisolate on Palo Alto Cortex XDR.
<br><strong>If you choose 'Unisolate One Endpoint'</strong><ul><li>Endpoint ID: If you select Unisolate One Endpoint, then in the Endpoint ID field specify the ID of the endpoint you want to unisolate on Palo Alto Cortex XDR.</li></ul><strong>If you choose 'Unisolate More Than One Endpoint'</strong><ul><li>Endpoint ID List: If you select Unisolate More Than One Endpoint, then in the Endpoint ID List field specify a list of endpoint IDs you want to unisolate on Palo Alto Cortex XDR.</li></ul></td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident to include the Unisolate Endpoints action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "action_id": []
    }
}</pre>
### operation: Get All Endpoints
#### Input parameters
None.
#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": [
        {
            "agent_id": "",
            "agent_status": "",
            "host_name": "",
            "agent_type": "",
            "ip": ""
        }
    ]
}</pre>
### operation: Get Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>(Optional) Specify the list of endpoint IDs that you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Distribution Name</td><td>(Optional) Specify the name of the distribution list or installation package name containing the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Group Name</td><td>(Optional) Specify the name of the group containing the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Alias</td><td>(Optional) Specify the alias of the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Hostname</td><td>(Optional) Specify the name of the host of the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Username</td><td>(Optional) Specify the name of the user associated with the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Endpoint Status</td><td>(Optional) Select the status of the endpoints to be retrieved from Palo Alto Cortex XDR. You can choose between Connected, Disconnected, Lost, or Uninstalled.
</td></tr><tr><td>IP List</td><td>(Optional) Specify the list of IP addresses containing the endpoints to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Platform</td><td>(Optional) Select the type of operating system that contains the endpoints to be retrieved from Palo Alto Cortex XDR. You can choose between Windows, Linux, Macos, or Android.
</td></tr><tr><td>Isolate</td><td>(Optional) Select the isolation status of the endpoints to be retrieved from Palo Alto Cortex XDR. Select Isolated to retrieve endpoints that are isolated and Unisolated to retrieve endpoints that are unisolated.
</td></tr><tr><td>Scan Status</td><td>(Optional) Select the scan status of endpoints to be retrieved from Palo Alto Cortex XDR. You can choose between None, Pending, In Progress, Cancelled, Aborted, Pending Cancellation, Sucess, or Error. you can choose from None, Pending, In Progress, Canceled, Aborted, Pending Cancellation, Success and Error
</td></tr><tr><td>First Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time later than the time specified.
</td></tr><tr><td>First Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Last Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time later than the time specified.
</td></tr><tr><td>Last Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Search From</td><td>(Optional) Specify the integer representing the starting offset within the query result set from which you want this operation to return endpoints from Palo Alto Cortex XDR.
</td></tr><tr><td>Search To</td><td>(Optional) Specify the integer representing the end offset within the result set after which you do not want this operation to return endpoints from Palo Alto Cortex XDR.
</td></tr><tr><td>Sort by Field</td><td>(Optional) Select the field by which you want to sort the endpoints retrieved by this operation. You can choose between first_seen or last_seen.
</td></tr><tr><td>Sort by Order</td><td>(Optional) Select this option to order the endpoints retrieved by this operation. You can choose between asc (ascending) or desc (Descending).
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "result_count": "",
        "endpoints": [
            {
                "endpoint_id": "",
                "endpoint_name": "",
                "endpoint_type": "",
                "endpoint_status": "",
                "os_type": "",
                "ip": "",
                "users": [
                    ""
                ],
                "domain": "",
                "alias": "",
                "first_seen": "",
                "last_seen": "",
                "content_version": "",
                "installation_package": "",
                "active_directory": "",
                "install_date": "",
                "endpoint_version": "",
                "is_isolated": "",
                "group_name": ""
            }
        ]
    }
}</pre>
### operation: Scan Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>(Optional) Specify the list of endpoint IDs that you want to scan on Palo Alto Cortex XDR.
</td></tr><tr><td>Distribution Name</td><td>(Optional) Specify the name of the distribution list containing the endpoints that you want to scan on Palo Alto Cortex XDR.
</td></tr><tr><td>Group Name</td><td>(Optional) Specify the name of the group containing the endpoints that you want to scan on Palo Alto Cortex XDR.
</td></tr><tr><td>Alias</td><td>(Optional) Specify the alias of the endpoints to be scanned on Palo Alto Cortex XDR.
</td></tr><tr><td>Hostname</td><td>(Optional) Specify the name of the host of the endpoints to be scanned on Palo Alto Cortex XDR.
</td></tr><tr><td>Username</td><td>(Optional) Specify the name of the user associated with the endpoints to be scanned on Palo Alto Cortex XDR.
</td></tr><tr><td>IP List</td><td>(Optional) Specify the list of IP addresses containing the endpoints to be scanned on Palo Alto Cortex XDR.
</td></tr><tr><td>Platform</td><td>(Optional) Select the type of operating system that contains the endpoints to be scanned on Palo Alto Cortex XDR. You can choose between Windows, Linux, Macos, or Android.
</td></tr><tr><td>Isolate</td><td>(Optional) Select the isolation status of the endpoints to be scanned on Palo Alto Cortex XDR. Select Isolated to retrieve endpoints that are isolated and Unisolated to retrieve endpoints that are unisolated.
</td></tr><tr><td>Scan Status</td><td>(Optional) Select the scan status of endpoints to be scanned on Palo Alto Cortex XDR. You can choose between None, Pending, In Progress, Cancelled, Aborted, Pending Cancellation, Sucess, or Error. you can choose from None, Pending, In Progress, Canceled, Aborted, Pending Cancellation, Success and Error
</td></tr><tr><td>First Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time later than the time specified.
</td></tr><tr><td>First Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Last Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time later than the time specified.
</td></tr><tr><td>Last Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident to include the Scan Endpoints action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "action_id": []
    }
}</pre>
### operation: Cancel Scan Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>(Optional) Specify the list of endpoint IDs whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Distribution Name</td><td>(Optional) Specify the name of the distribution list containing the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Group Name</td><td>(Optional) Specify the name of the group containing the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Alias</td><td>(Optional) Specify the alias of the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Hostname</td><td>(Optional) Specify the name of the host of the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Username</td><td>(Optional) Specify the name of the user associated with the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>IP List</td><td>(Optional) Specify the list of IP addresses containing the endpoints whose scan you want to cancel on Palo Alto Cortex XDR.
</td></tr><tr><td>Platform</td><td>(Optional) Select the type of operating system that contains the endpoints whose scan you want to cancel on Palo Alto Cortex XDR. You can choose between Windows, Linux, Macos, or Android.
</td></tr><tr><td>Isolate</td><td>(Optional) Select the isolation status of the endpoints whose scan you want to cancel on Palo Alto Cortex XDR. Select Isolated to retrieve endpoints that are isolated and Unisolated to retrieve endpoints that are unisolated.
</td></tr><tr><td>Scan Status</td><td>(Optional) Select the scan status of endpoints whose scan you want to cancel on Palo Alto Cortex XDR. You can choose between None, Pending, In Progress, Cancelled, Aborted, Pending Cancellation, Sucess, or Error. you can choose from None, Pending, In Progress, Canceled, Aborted, Pending Cancellation, Success and Error
</td></tr><tr><td>First Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time later than the time specified.
</td></tr><tr><td>First Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were first seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Last Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time later than the time specified.
</td></tr><tr><td>Last Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints retrieved by this operation to include only those endpoints that were last seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident to include the Cancel Scan Endpoints action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Delete Endpoints
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>Specify a list of endpoint IDs that you want to delete from the Palo Alto Cortex XDR app.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Get Policy
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>Specify a string that represents the endpoint ID for which you want to retrieve the policy from Palo Alto Cortex XDR. For example, 51588e4ce9214c63b39d054bd073b93a
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "policy_name": ""
    }
}</pre>
### operation: Get Device Violations
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>(Optional) Specify the list of endpoint IDs based on which you want to retrieve violations from Palo Alto Cortex XDR.
</td></tr><tr><td>Vendor</td><td>(Optional) Specify the string value that defines the vendor whose associated violations are to be retrieved from Palo Alto Cortex XDR. For example, Check Point
</td></tr><tr><td>Vendor ID</td><td>(Optional) Specify the string value that defines the vendor ID whose associated violations are to be retrieved from Palo Alto Cortex XDR. For example, 0x0999
</td></tr><tr><td>Product</td><td>(Optional) Specify the string value that defines the product whose associated violations are to be retrieved from Palo Alto Cortex XDR. For example, VPN & Firewall-1
</td></tr><tr><td>Product ID</td><td>(Optional) Specify the string value that defines the product ID whose associated violations are to be retrieved from Palo Alto Cortex XDR. For example, 0x10036
</td></tr><tr><td>Serial</td><td>(Optional) Specify the string value that defines the serial number whose associated violations are to be retrieved from Palo Alto Cortex XDR. For example, 8888889
</td></tr><tr><td>Hostname</td><td>(Optional) Specify the name of the host whose associated violations are to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Username</td><td>(Optional) Specify the name of the user whose associated violations are to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Type</td><td>(Optional) Select the type of violations that are to be retrieved from Palo Alto Cortex XDR. You can choose between CD ROM, Disk Drive, Floppy Disk, or Portable Device.
</td></tr><tr><td>IP List</td><td>(Optional) Specify the list of IP addresses whose associated violations are to be retrieved from Palo Alto Cortex XDR.
</td></tr><tr><td>Violation ID List</td><td>(Optional) Specify the list of violation IDs that you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Timestamp After</td><td>(Optional) Timestamp of the violation.
</td></tr><tr><td>Timestamp Before</td><td>(Optional) Timestamp of the violation.
</td></tr><tr><td>Search From</td><td>(Optional) Specify the integer representing the starting offset within the query result set from which you want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Search To</td><td>(Optional) Specify the integer representing the end offset within the result set after which you do not want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Sort by Field</td><td>(Optional) Select the field by which you want to sort the endpoints retrieved by this operation. You can from options such as serial, product, username, etc. you can choose from endpoint_id_list, type, timestamp, ip_list, vendor, vendor_id, product, product_id, serial, hostname, violation_id_list and username
</td></tr><tr><td>Sort by Order</td><td>(Optional) Select this option to order the endpoints retrieved by this operation. You can choose between asc (ascending) or desc (Descending).
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "result_count": "",
        "violations": [
            {
                "hostname": "",
                "username": "",
                "ip": "",
                "timestamp": "",
                "violation_id": "",
                "type": "",
                "vendor_id": "",
                "vendor": "",
                "product_id": "",
                "product": "",
                "serial": "",
                "endpoint_id": ""
            }
        ]
    }
}</pre>
### operation: Get Distribution Version
#### Input parameters
None.
#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "windows": [],
        "linux": [],
        "macos": []
    }
}</pre>
### operation: Create Distributions
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Name</td><td>Specify the string representing the name of the installation package that you want to create on Palo Alto Cortex XDR.
</td></tr><tr><td>Package Type</td><td>Select the type of installation package that you want to create on Palo Alto Cortex XDR. You can choose from the following types: Standalone or Upgrade. If you choose the 'Standalone' operator, then from the Platform drop-down list, select the platform on which you want to create the installation package. You can choose the following: Windows, Linux, Macos, or Android. Also if you choose 'Windows', 'Macos', or 'Linux', then in the Agent Version field, enter the version of the agent. For example, 5.0.7.16157 . If you choose the 'Upgrade' operator, then in the Upgrade field, specify the version of an agent that you want to upgrade from ESM. You can specify the following values: windows_version, linux_version, or macos_version.
<br><strong>If you choose 'Standalone'</strong><ul><li>Platform: If you choose the 'Standalone' operator, then from the Platform drop-down list, select the platform on which you want to create the installation package. You can choose the following: Windows, Linux, Macos, or Android. Also if you choose 'Windows', 'Macos', or 'Linux', then in the Agent Version field, enter the version of the agent. For example, 5.0.7.16157.</li><strong>If you choose 'Windows'</strong><ul><li>Agent Version: The version of agent. e.g. 5.0.7.16157</li></ul><strong>If you choose 'Linux'</strong><ul><li>Agent Version: The version of agent. e.g. 5.0.7.16157</li></ul><strong>If you choose 'Macos'</strong><ul><li>Agent Version: The version of agent. e.g. 5.0.7.16157</li></ul></ul><strong>If you choose 'Upgrade'</strong><ul><li>Upgrade: If you choose the 'Upgrade' operator, then in the Upgrade field, specify the version of an agent that you want to upgrade from ESM. You can specify the following values: windows_version, linux_version, or macos_version.</li></ul></td></tr><tr><td>Description</td><td>Specify the string containing descriptive information about the installation package.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "distribution_id": ""
    }
}</pre>
### operation: Get Distribution Status
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Distribution ID</td><td>Specify the string representing the ID of the installation package whose status you want to retrieve from Palo Alto Cortex XDR.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "status": ""
    }
}</pre>
### operation: Get Distribution URL
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Distribution ID</td><td>Specify the string representing the ID of the installation package whose distribution URL you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Package Type</td><td>Select the type of installation package whose distribution URL you want to retrieve from Palo Alto Cortex XDR. You can choose from the following options: sh-For Linux, rpm-For Linux, deb-For Linux, pkg-For Mac, x86-For Windows, or x64-For Windows. you can choose from sh—For Linux, rpm—For Linux, deb—For Linux, pkg—For Mac, x86—For Windows and x64—For Windows
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "distribution_url": ""
    }
}</pre>
### operation: Get Audit Management Logs
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Email</td><td>(Optional) Specify the email address of the user whose audit management logs you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Type</td><td>(Optional) Specify the type of audit management logs you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Sub Type</td><td>(Optional) Specify the sub-type of the audit management logs you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Result</td><td>(Optional) Specify the result of the audit log using which you want to filter the audit log management logs retrieved from Palo Alto Cortex XDR. For example, SUCCESS.
</td></tr><tr><td>Timestamp After</td><td>(Optional) Select the DateTime of the log till when you want to retrieve audit management logs from Palo Alto Cortex XDR. This operator will retrieve all audit management logs whose timestamp matches the time specified or the time later than the time specified on Palo Alto Cortex XDR.
</td></tr><tr><td>Timestamp Before</td><td>(Optional) Select the DateTime of the log from when you want to retrieve audit management logs from Palo Alto Cortex XDR. This operator will retrieve all audit management logs whose timestamp matches the time specified or the time earlier than the time specified on Palo Alto Cortex XDR.
</td></tr><tr><td>Search From</td><td>(Optional) Specify an integer representing the starting offset within the query result set from which you want management logs returned.
</td></tr><tr><td>Search To</td><td>(Optional) Specify an integer representing the end offset within the result set after which you do not want management logs returned.
</td></tr><tr><td>Sort by Field</td><td>(Optional) Select the field by which you want to sort the audit management logs retrieved by this operation. You can choose between type, sub-type, or result.
</td></tr><tr><td>Sort by Order</td><td>(Optional) Select this option to order the audit management logs retrieved by this operation. You can choose between asc (ascending) or desc (Descending).
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "result_count": "",
        "data": [
            {
                "AUDIT_ID": "",
                "AUDIT_OWNER_NAME": "",
                "AUDIT_OWNER_EMAIL": "",
                "AUDIT_ASSET_JSON": "",
                "AUDIT_ASSET_NAMES": "",
                "AUDIT_HOSTNAME": "",
                "AUDIT_RESULT": "",
                "AUDIT_REASON": "",
                "AUDIT_DESCRIPTION": "",
                "AUDIT_ENTITY": "",
                "AUDIT_ENTITY_SUBTYPE": "",
                "AUDIT_SESSION_ID": "",
                "AUDIT_CASE_ID": "",
                "AUDIT_INSERT_TIME": ""
            }
        ]
    }
}</pre>
### operation: Get Audit Agent Report
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>(Optional) Specify the string representing the ID of the endpoint whose associated audit agent reports you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Endpoint Name</td><td>(Optional) Specify the string representing the name of the endpoint whose associated audit agent reports you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Type</td><td>(Optional) Specify the type of audit agent reports you want to retrieve from Palo Alto Cortex XDR. For example, Agent Status.
</td></tr><tr><td>Sub Type</td><td>(Optional) Specify the sub-type of the audit agent reports you want to retrieve from Palo Alto Cortex XDR. For example, Fully Protected.
</td></tr><tr><td>Result</td><td>(Optional) Specify the result of the agent report using which you want to filter the audit agent reports retrieved from Palo Alto Cortex XDR. For example, SUCCESS.
</td></tr><tr><td>Domain</td><td>(Optional) Specify the domain of the agent whose audit agent reports you want to retrieve from Palo Alto Cortex XDR. For example, WORKGROUP.
</td></tr><tr><td>xdr_version</td><td>(Optional) Specify the XDR version for which you want to retrieve audit agent reports from Palo Alto Cortex XDR.
</td></tr><tr><td>Category</td><td>(Optional) Select the type of event category of the audit agent reports you want to retrieve from Palo Alto Cortex XDR. You can choose from the following options: Status, Audit, or Monitoring.
</td></tr><tr><td>Timestamp After</td><td>(Optional) Datetime of the report till when you want to retrieve audit management logs from Palo Alto Cortex XDR. This operator will retrieve all audit agent reports whose timestamp matches the time specified or the time later than the time specified on Palo Alto Cortex XDR.
</td></tr><tr><td>Timestamp Before</td><td>(Optional) Datetime of the report from when you want to retrieve audit management logs from Palo Alto Cortex XDR. This operator will retrieve all audit agent reports whose timestamp matches the time specified or the time earlier than the time specified on Palo Alto Cortex XDR.
</td></tr><tr><td>Search From</td><td>(Optional) Specify an integer representing the starting offset within the query result set from which you want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Search To</td><td>(Optional) Specify an integer representing the end offset within the result set after which you do not want this operation to return incidents from Palo Alto Cortex XDR.
</td></tr><tr><td>Sort by Field</td><td>(Optional) Select the field by which you want to sort the audit management logs retrieved by this operation. You can choose between type, category, trapsversion, timestamp, or domain.
</td></tr><tr><td>Sort by Order</td><td>(Optional) Select this option to order the audit management logs retrieved by this operation. You can choose between asc (ascending) or desc (Descending).
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "result_count": "",
        "data": [
            {
                "TIMESTAMP": "",
                "RECEIVEDTIME": "",
                "ENDPOINTID": "",
                "ENDPOINTNAME": "",
                "DOMAIN": "",
                "TRAPSVERSION": "",
                "CATEGORY": "",
                "TYPE": "",
                "SUBTYPE": "",
                "RESULT": "",
                "REASON": "",
                "DESCRIPTION": ""
            }
        ]
    }
}</pre>
### operation: Blacklist Files
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Hash List</td><td>Specify a string that represents a list of file hash values you want to blacklist on Palo Alto Cortex XDR. Note: Hash must be a valid SHA256 value. 
</td></tr><tr><td>Comment</td><td>(Optional) Specify a string containing descriptive information about this action.
</td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident related to the specified file hash to include the Blacklist Files action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Whitelist Files
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Hash List</td><td>Specify a string that represents a list of file hash values you want to whitelist on Palo Alto Cortex XDR. Note: The hash must be a valid SHA256 value.
</td></tr><tr><td>Comment</td><td>(Optional) Specify a string containing descriptive information about this action.
</td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident related to the specified file hash to include the Blacklist Files action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": ""
}</pre>
### operation: Quarantine Files
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>Specify a list of endpoint IDs representing the endpoints on which you want to quarantine files on Palo Alto Cortex XDR.
</td></tr><tr><td>File Path</td><td>Specify the string representing the path of the file you want to quarantine on the specified endpoints on Palo Alto Cortex XDR.
</td></tr><tr><td>File Hash</td><td>Specify the string representing the hash value of the file you want to quarantine on the specified endpoints on Palo Alto Cortex XDR. Note: The hash must be a valid SHA256 value.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "action_id": []
    }
}</pre>
### operation: Get Quarantine Status
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID</td><td>Specify the string representing the endpoint ID whose associated files' quarantine status you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>File Hash</td><td>Specify the string representing the hash value of the file whose quarantine status you want to retrieve from Palo Alto Cortex XDR. Note: The hash must be a valid SHA256 value.
</td></tr><tr><td>File Path</td><td>Specify the string representing the path of the file whose quarantine status you want to retrieve from Palo Alto Cortex XDR.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": [
        {
            "endpoint_id": "",
            "file_path": "",
            "file_hash": "",
            "status": ""
        }
    ]
}</pre>
### operation: Restore File
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>File Hash</td><td>Specify the string representing the hash value of the quarantined file that you want to restore on the specified endpoint on Palo Alto Cortex XDR. Note: The hash must be a valid SHA256 value.
</td></tr><tr><td>Endpoint ID</td><td>(Optional) Specify the string representing the endpoint ID on which you want to restore the specified quarantined file.
</td></tr><tr><td>Incident ID</td><td>(Optional) Specify the ID of the incident related to the specified file hash to include the Restore Files action in the Cortex XDR Incident ViewTimeline tab.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "message": "",
    "status": ""
}</pre>
### operation: Retrieve File
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Endpoint ID List</td><td>Specify the list of endpoint IDs whose associated files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Files</td><td>Select the type of operating system from which you want to retrieve files from Palo Alto Cortex XDR. You can choose between Windows, Linux, or Macos.
</td></tr><tr><td>File Path</td><td>Specify the string representing the path of the file used to retrieve files from Palo Alto Cortex XDR.
</td></tr><tr><td>Distribution Name</td><td>(Optional) Specify the string representing the name of the distribution list containing the files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Group Name</td><td>(Optional) Specify the string representing the name of the endpoint group containing the files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Alias</td><td>(Optional) Specify the string representing the alias of the endpoints whose associated files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Hostname</td><td>(Optional) Specify the string representing the name of the host of the endpoints whose associated files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>IP List</td><td>(Optional) Specify the string representing the list of IP addresses containing the endpoints whose associated files you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Platform</td><td>(Optional) Select the type of operating system that contains the endpoints whose associated files you want to retrieve from Palo Alto Cortex XDR. You can choose between Windows, Linux, Macos, or Android.
</td></tr><tr><td>Isolate</td><td>(Optional) Select the isolation status of the endpoints whose associated files you want to retrieve from Palo Alto Cortex XDR. Select Isolated to retrieve endpoints that are isolated and Unisolated to retrieve endpoints that are unisolated.
</td></tr><tr><td>First Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints, whose associated files you want to be retrieved by this operation to include only those endpoints that were first seen at the time specified or the time later than the time specified.
</td></tr><tr><td>Last Seen After</td><td>(Optional) Select the DateTime using which you want to filter the endpoints, whose associated files you want to be retrieved by this operation to include only those endpoints that were last seen at the time specified or the time later than the time specified.
</td></tr><tr><td>First Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints, whose associated files you want to be retrieved by this operation to include only those endpoints that were first seen at the time specified or the time earlier than the time specified.
</td></tr><tr><td>Last Seen Before</td><td>(Optional) Select the DateTime using which you want to filter the endpoints, whose associated files you want to be retrieved by this operation to include only those endpoints that were last seen at the time specified or the time earlier than the time specified.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "action_id": "",
        "endpoints_count": ""
    }
}</pre>
### operation: Retrieve File Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Action ID</td><td>Specify the ID of the action ID whose associated file details you want to retrieve from Palo Alto Cortex XDR.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "reply": {
        "data": {}
    }
}</pre>
### operation: Execute XQL Query
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Query</td><td>Specify the XQl query you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Tenants ID</td><td>(Optional) Specify the tenants to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Start Datetime</td><td>(Optional) Specify the start date of the time range within which to search for and retrieve incidents.
</td></tr><tr><td>End Datetime</td><td>(Optional) Specify the end date of the time range within which to search for and retrieve incidents.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.
### operation: Get Query Results By Query ID
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Query ID</td><td>Specify the XQl query you want to retrieve from Palo Alto Cortex XDR.
</td></tr><tr><td>Pending Flag</td><td>(Optional) Indicates whether the API call should operate in synchronous/blocking mode, or in asynchronous/non-blocking mode you can choose from true and false
</td></tr><tr><td>Limit</td><td>(Optional) Integer representing the maximum number of results to return. If the 'limit' is not specified or if 'limit' is greater than 1000 and the query yields more than 1000 valid results, a stream id will be generated for use in the Get XQL Query Results Stream* API. In the context of multi-tenant investigations, when you specify the parameter value (x), it will return x results across all tenants combined, rather than x results for each individual tenant. For example, if there are y tenants participating in the investigation, the maximum number of results returned can be x*y (up to the limit of 1,000,000).
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.
## Included playbooks
The `Sample - paloalto-cortex-xdr - 1.2.0` playbook collection comes bundled with the Palo Alto Cortex XDR connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the Palo Alto Cortex XDR connector.

- Blacklist Files
- Cancel Scan Endpoints
- Cortex > Create Incident
- Cortex > Fetch
- Cortex > Ingest
- Create Distributions
- Delete Endpoints
- Fetch Incidents
- Get All Endpoints
- Get Audit Agent Report
- Get Audit Management Logs
- Get Device Violations
- Get Distribution Status
- Get Distribution URL
- Get Distribution Version
- Get Endpoints
- Get Incident Details
- Get Policy
- Get Quarantine Status
- Get Query Results By Query ID
- Insert CEF Alerts
- Insert Parsed Alerts
- Isolate Endpoints
- Quarantine Files
- Restore File
- Retrieve File
- Scan Endpoints
- Unisolate Endpoints
- Update Incident
- Whitelist Files
- XQL Query

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
