"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import arrow
import copy
import datetime
import hashlib
import json
import os
import requests
import secrets
import string
import time
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from datetime import datetime, timezone, timedelta
from django.conf import settings
from json import dumps

from .constants import *

logger = get_logger('paloalto-coretx-xdr')


class CortexXdr():
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if self.server_url.startswith('https://') or self.server_url.startswith('http://'):
            self.server_url = self.server_url.strip('/') + '/public_api/v1'
        else:
            self.server_url = 'https://{0}'.format(self.server_url.strip('/')) + '/public_api/v1'
        self.api_key_id = config.get('api_key_id')
        self.api_key = config.get('api_key')
        self.authentication_type = config.get('authentication_type')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):
        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)
        if flag:
            url = endpoint
        logger.info('Request URL {}'.format(url))
        if self.authentication_type == 'Standard Key':
            headers = {"x-xdr-auth-id": str(self.api_key_id), "Authorization": self.api_key,
                       "Content-Type": "application/json"}
        else:
            nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
            timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
            auth_key = "%s%s%s" % (self.api_key, nonce, timestamp)
            auth_key = auth_key.encode("utf-8")
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            headers = {"x-xdr-timestamp": str(timestamp), "x-xdr-nonce": nonce, "x-xdr-auth-id": str(self.api_key_id),
                       "Authorization": api_key_hash}
        try:
            # CURL UTILS CODE
            try:
                from connectors.debug_utils.curl_script import make_curl
                json_data = dumps(json) if json else data
                make_curl(method, url, headers=headers, params=params, data=json_data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.debug(f"Error in curl utils: {str(err)}")
            response = requests.request(method=method, url=url, params=params, data=data, json=json, headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                if response.headers.get('Content-Disposition'):
                    return response
                result = response.json()
                if result.get('error'):
                    raise ConnectorError('{}'.format(result.get('error').get('message')))
                if response.status_code == 204:
                    return {"Status": "Success", "Message": "Executed successfully"}
                return result
            elif messages_codes.get(response.status_code):
                logger.error('{}: {}'.format(response.status_code, response.text))
                raise ConnectorError('{}'.format(messages_codes[response.status_code]))
            else:
                logger.error(
                    'Fail To request API {0} response is : {1} with reason: {2}'.format(str(url),
                                                                                        str(response.content),
                                                                                        str(response.reason)))
                raise ConnectorError(
                    'Fail To request API {0} response is :{1} with reason: {2}'.format(str(url),
                                                                                       str(response.content),

                                                                                       str(response.reason)))

        except requests.exceptions.SSLError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(messages_codes['ssl_error']))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(messages_codes['timeout_error']))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


def build_payload(params):
    result = {k: v for k, v in params.items() if v is not None and v != ''}
    return result


def get_expiration_timestamp(days=None):
    if days == "Never":
        return "Never"
    elif days is None:
        return None
    elif isinstance(days, int):
        expiration_date = datetime.utcnow() + timedelta(days=days)
        return int(expiration_date.timestamp() * 1000)
    else:
        raise ValueError("Invalid input: Expiry days must be an integer, 'Never', or None")


def handle_list_parameter(key, value, result):
    if not isinstance(value, (list, tuple)):
        alerts = [x.strip() for x in value.split(',')]
        result['{key}'.format(key=key)] = alerts


def build_timestamp(key, value, result):
    str_time = time.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch_time = int(datetime.datetime.fromtimestamp(time.mktime(str_time)).strftime('%s')) * 1000
    result['{key}'.format(key=key)] = epoch_time


def build_filter_payload(result, keys, filters_list):
    filters_dict = {"field": "", "operator": "", "value": []}
    for k, v in result.items():
        if k in keys:
            filters_dict['operator'] = operator_mapping.get(result.get('operator'))
            filters_dict['field'] = k
            filters_dict['value'] = to_utimestamp(v) if 'time' in k else v
            filters_list.append(filters_dict)
            filters_dict = dict()


def check_health(config):
    try:
        logger.info("Invoking check_health")
        cortexxdr = CortexXdr(config)
        response = cortexxdr.make_api_call(method='POST', endpoint='/distributions/get_versions/')
        if response:
            return True
    except Exception as err:
        logger.error("{0}".format(err))
        raise ConnectorError("{0}".format(err))


def to_utimestamp(time_string):
    if len(time_string) > 0:
        return arrow.get(time_string).int_timestamp * 1000
    else:
        return arrow.now().int_timestamp * 1000


def build_query_payload(params):
    filters_list = []
    _payload = copy.deepcopy(payload)
    for k, v in params.items():
        if v is not None:
            if v and 'filter' in k:
                terms = k.split('.')
                if '_time' in k or '_seen' in k or 'timestamp' in k:
                    v = to_utimestamp(v)
                elif 'incident_id_list' in k or 'endpoint_id_list' in k:
                    if not isinstance(v, list):
                        v = [x.strip() for x in v.split(',')]
                    elif isinstance(v, list):
                        v = [str(x.strip) for x in v]
                elif 'status' in k:
                    v = status_mapping.get(v)
                filters_list.append({'field': terms[2], 'operator': terms[1], 'value': v})
            if isinstance(v, int) and 'cursor' in k:
                _payload['request_data'].update({k.split('.')[1]: v})
            if v and 'sort' in k:
                _payload['request_data']['sort'].update({k.split('.')[1]: v})

    if len(filters_list) > 0:
        _payload['request_data'].update({'filters': filters_list})
    return _payload


def fetch_incidents(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/incidents/get_incidents/'
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_incident_details(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/incidents/get_incident_extra_data/'
        payload = {
            "request_data": {
                "incident_id": str(params.get('incident_id'))
            }
        }
        if params.get('alerts_limit'):
            payload.get('request_data').update({"alerts_limit": params.get('alerts_limit')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def update_incident(config, params):
    try:
        obj = CortexXdr(config)
        if not (params.get('assigned_user_mail') or params.get('assigned_user_pretty_name') or params.get(
            'manual_severity') or params.get('status') or params.get('resolve_comment')):
            raise ConnectorError(
                'At least one of the [Assigned User Mail, Assigned User Pretty Name, Severity, Status, Resolve Comment] is required.')
        endpoint = '/incidents/update_incident/'
        result = build_payload(params)
        payload = {
            "request_data": {
                "incident_id": str(params.get('incident_id')),
                "update_data": {}
            }
        }
        result.pop('incident_id','')
        if result:
            if result.get('manual_severity'):
                result['manual_severity'] = severity_mapping.get(result.get('manual_severity'))
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
            payload.get('request_data').get('update_data').update(result)
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def insert_cef_alerts(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/alerts/insert_cef_alerts/'
        payload = {
            "request_data": {
            }
        }
        if not isinstance(params.get('alerts'), list):
            alerts = [x.strip() for x in params.get('alerts').split(',')]
            payload.get('request_data').update({"alerts": alerts})
        else:
            payload.get('request_data').update({"alerts": params.get('alerts')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def insert_parsed_alerts(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/alerts/insert_parsed_alerts/'
        result = build_payload(params)
        payload = {
            "request_data": {
                "alerts": []
            }
        }
        if result.get('event_timestamp'):
            str_time = time.strptime(result.get('event_timestamp'), "%Y-%m-%dT%H:%M:%S.%fZ")
            epoch_time = int(datetime.datetime.fromtimestamp(time.mktime(str_time)).strftime('%s')) * 1000
            result['event_timestamp'] = epoch_time
        if result.get('severity'):
            result['severity'] = severity_mapping.get(result.get('severity'))
        payload.get('request_data').get('alerts').append(result)
        response = obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def build_isolation_payload(params):
    payload = {
        "request_data": {}
    }
    filters = []
    incident_id = params.get('incident_id')
    if incident_id:
        payload.get('request_data', {}).update({'incident_id': incident_id})
    list_endpoints = params.get('isolate_endpoint', '')
    if isinstance(list_endpoints, str):
        list_endpoints = list_endpoints.split(',')
    if isinstance(list_endpoints, list):
        list_endpoints = [endpoint.strip() for endpoint in list_endpoints]
    if isinstance(list_endpoints, list) and len(list_endpoints) == 1:
        list_endpoints = "".join(list_endpoints)
        payload.get('request_data', {}).update({'endpoint_id': list_endpoints})
    else:
        if list_endpoints and isinstance(list_endpoints, list):
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": list_endpoints})
    if len(filters) > 0:
        payload.get('request_data', {}).update({'filters': filters})
    return payload


def isolate_endpoints(config, params):
    try:
        xdr_client = CortexXdr(config)
        payload = build_isolation_payload(params)
        return xdr_client.make_api_call(method='POST', endpoint='/endpoints/isolate/', json=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def unisolate_endpoints(config, params):
    try:
        xdr_client = CortexXdr(config)
        payload = build_isolation_payload(params)
        return xdr_client.make_api_call(method='POST', endpoint='/endpoints/unisolate/', json=payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_all_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/get_endpoints/'
        response = obj.make_api_call(method='POST', endpoint=endpoint)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/get_endpoint/'
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def scan_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/scan/'
        query_payload = build_query_payload(params)
        if params.get('incident_id'):
            query_payload.get('request_data').update({"incident_id": params.get('incident_id')})
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def cancel_scan_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/abort_scan/'
        query_payload = build_query_payload(params)
        if params.get('incident_id'):
            query_payload.get('request_data').update({"incident_id": params.get('incident_id')})
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def delete_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/delete/'
        result = build_payload(params)
        handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_policy(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/get_policy/'
        payload = {
            "request_data": {
                "endpoint_id": params.get('endpoint_id')
            }
        }
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_device_violations(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/device_control/get_violations/'
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_distribution_version(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/distributions/get_versions/'
        response = obj.make_api_call(method='POST', endpoint=endpoint)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def create_distributions(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/distributions/create/'
        payload = {
            "request_data": {
                "name": params.get('name')
            }
        }
        if params.get('package_type') == 'Standalone':
            if params.get('platform') == 'Android':
                payload.get('request_data').update({"package_type": "Standalone", "platform": params.get('platform')})
            else:
                payload.get('request_data').update({"package_type": "Standalone", "platform": params.get('platform'),
                                                    "agent_version": params.get('agent_version')})
        elif params.get('package_type') == 'Upgrade':
            payload.get('request_data').update({"package_type": {"upgrade": [params.get('upgrade')]}})
        if params.get('description'):
            payload.get('request_data').update({"description": params.get('description')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_distribution_status(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/distributions/get_status/'
        payload = {
            "request_data": {
                "distribution_id": params.get('distribution_id')
            }
        }
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_distribution_url(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/distributions/get_dist_url/'
        payload = {
            "request_data": {
                "distribution_id": params.get('distribution_id'),
                "package_type": package_type.get(params.get('package_type'))
            }
        }
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_audit_management_log(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/audits/management_logs/'
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_audit_agent_report(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/audits/agents_reports/'
        query_payload = build_query_payload(params)
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def blacklist_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/hash_exceptions/blocklist/'
        payload = {
            "request_data": {
            }
        }
        if not isinstance(params.get('hash_list'), list):
            alerts = [x.strip() for x in params.get('hash_list').split(',')]
            payload.get('request_data').update({"hash_list": alerts})
        if params.get('comment'):
            payload.get('request_data').update({"comment": params.get('comment')})
        if params.get('incident_id'):
            payload.get('request_data').update({"incident_id": params.get('incident_id')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def whitelist_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/hash_exceptions/allowlist/'
        payload = {
            "request_data": {
            }
        }
        if not isinstance(params.get('hash_list'), list):
            alerts = [x.strip() for x in params.get('hash_list').split(',')]
            payload.get('request_data').update({"hash_list": alerts})
        if params.get('comment'):
            payload.get('request_data').update({"comment": params.get('comment')})
        if params.get('incident_id'):
            payload.get('request_data').update({"incident_id": params.get('incident_id')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def quarantine_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/quarantine/'
        query_payload = build_query_payload(params)
        query_payload.get('request_data').update({"file_path": params.get('file_path')})
        query_payload.get('request_data').update({"file_hash": params.get('file_hash')})
        return obj.make_api_call(method='POST', endpoint=endpoint, json=query_payload)
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_quarantine_status(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/quarantine/status/'
        payload = {
            "request_data": {
                "files": [
                ]
            }
        }
        files_dict = {"endpoint_id": params.get('endpoint_id'), "file_hash": params.get('file_hash'),
                      "file_path": params.get('file_path')}
        payload.get('request_data').get('files').append(files_dict)
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def restore_file(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/restore/'
        payload = {
            "request_data": {
                "file_hash": params.get('file_hash')
            }
        }
        if params.get('endpoint_id'):
            payload.get('request_data').update({"endpoint_id": params.get('endpoint_id')})
        if params.get('incident_id'):
            payload.get('request_data').update({"incident_id": params.get('incident_id')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def retrieve_file(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/file_retrieval/'
        query_payload = build_query_payload(params)
        files = {"files": {platform_mapping.get(params.get('files')): [params.get('file_path')]}}
        query_payload['request_data'].update(files)
        action_id_response = obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(query_payload))
        params_dict = {"group_action_id": action_id_response.get('reply').get('action_id')}
        import time
        time.sleep(20)

        download_link_response = retrieve_file_details(config, params_dict)
        file_link = download_link_response.get('reply').get('data')
        file_data = obj.make_api_call(method='POST', endpoint=list(file_link.values())[0], flag=True)
        attachment = file_data.headers.get('Content-Disposition')
        attachment = attachment.split(';')
        file_name = attachment[1].split('=')[1]
        path = os.path.join(settings.TMP_FILE_ROOT, file_name)
        logger.error("Path: {0}".format(path))
        with open(path, 'wb') as fp:
            fp.write(file_data.content)
        attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                               name=file_name, create_attachment=True)
        return attach_response


    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def retrieve_file_details(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/actions/file_retrieval_details/'

        payload = {
            "request_data": {
                "group_action_id": params.get('group_action_id')
            }
        }
        return obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def xql_query(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/xql/start_xql_query'
        tenants = params.get('tenants')
        if tenants:
            tenants = tenants.split(',')
        else:
            tenants = []
        strat = params.get('from')
        end = params.get('to')
        if strat and end:
            start_time = int(datetime.fromtimestamp(time.mktime(
                time.strptime(strat, "%Y-%m-%dT%H:%M:%S.%fZ")
            )).strftime('%s')) * 1000
            end_time = int(datetime.fromtimestamp(time.mktime(
                time.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
            )).strftime('%s')) * 1000
        else:
            relative_time = 86400000  # 24 hours in milliseconds
            current_time = int(time.time() * 1000)
            start_time = current_time - relative_time
            end_time = current_time

        payload = {
            "request_data": {
                "query": params.get('query'),
                "tenants": tenants,
                "timeframe": {
                    "from": start_time,
                    "to": end_time
                }
            }
        }
        return obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))


def get_query_result_by_query_id(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/xql/get_query_results'
        payload = {
            "request_data": {
                "query_id": params.get('query_id'),
                "pending_flag": params.get('pending_flag'),
                "limit": params.get('limit'),
                "format": "json"
            }
        }
        return obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))


def update_alerts(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/alerts/update_alerts'
        status_input = params.get("status")
        status_value = ALERT_STATUS_MAPPING.get(status_input) if status_input else None
        update_data = {
            "severity": (params.get('severity') or '').lower(),
            "status": status_value,
            "comment": params.get('comment')
        }
        update_data = build_payload(update_data)
        if not update_data:
            raise ConnectorError('At least one of the following parameter is required: Status, Severity, or Comment.')
        alert_ids = params.get("alert_ids")
        if isinstance(alert_ids, int):
            alert_ids = [str(alert_ids)]
        elif isinstance(alert_ids, str):
            alert_ids = [x.strip() for x in alert_ids.split(',')]
        elif isinstance(alert_ids, list):
            alert_ids = [str(x) for x in alert_ids]
        else:
            raise ConnectorError("Invalid alert_ids format")
        payload = {
            "request_data": {
                "alert_id_list": alert_ids,
                "update_data": update_data
            }
        }
        handle_list_parameter("alert_id_list", params.get('alert_ids'), payload["request_data"])
        return obj.make_api_call(method='POST', endpoint=endpoint, data=json.dumps(payload))
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_alerts(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/alerts/get_alerts/'
        filters = []
        query_payload = {
            'filters': filters,
            'search_from': params.get('search_from'),
            'search_to': params.get('search_to'),
            'sort': {
                'field': 'severity' if params.get('sort_field') == 'severity' else 'creation_time',
                'keyword': 'asc' if params.get('sort_order') == 'Ascending' else 'desc'
            }
        }
        for field in ['alert_id_list', 'alert_source', 'severity', 'creation_time_gte', 'creation_time_lte']:
            value = params.get(field)
            if value:
                if 'creation_time' in field:
                    operator = 'gte' if 'gte' in field else 'lte'
                    field = 'creation_time'
                    value = to_utimestamp(value)
                else:
                    operator = 'in'
                    value = [i.strip() for i in value.split(',')] if isinstance(value, str) else value
                filter_obj = {
                    'field': field,
                    'operator': operator,
                    'value': value
                }
                filters.append(filter_obj)
        query_payload = build_payload(query_payload)
        return obj.make_api_call(method='POST', endpoint=endpoint, json={'request_data': query_payload})
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def insert_simple_indicators(config, params):
    try:
        xdr_client = CortexXdr(config)
        endpoint = '/indicators/insert_jsons'
        result = build_payload(params)
        payload_data = {
            "request_data": [],
            "validate": result.pop('validate', False)
        }
        expiry = result.pop('expiry', 'Default')
        result['expiration_date'] = get_expiration_timestamp(expiration_days_map.get(expiry, None))
        if result.get('severity'):
            result['severity'] = 'unknown' if result.get('severity') == 'Unknown' else severity_mapping.get(
                result.get('severity'), '').upper()
        if result.get('reputation'):
            result['reputation'] = REPUTATION_MAPPING.get(result.get('reputation'))
        if result.get('type'):
            result['type'] = INDICATOR_TYPE_MAPPING.get(result.get('type'))
        payload_data['request_data'].append(result)
        return xdr_client.make_api_call(method='POST', endpoint=endpoint, json=payload_data)
    except Exception as Err:
        logger.error(f'Exception occurred: {Err}')
        raise ConnectorError(Err)


operations = {
    'fetch_incidents': fetch_incidents,
    'get_incident_details': get_incident_details,
    'update_incident': update_incident,
    'insert_cef_alerts': insert_cef_alerts,
    'insert_parsed_alerts': insert_parsed_alerts,
    'isolate_endpoints': isolate_endpoints,
    'unisolate_endpoints': unisolate_endpoints,
    'get_all_endpoints': get_all_endpoints,
    'get_endpoints': get_endpoints,
    'scan_endpoints': scan_endpoints,
    'cancel_scan_endpoints': cancel_scan_endpoints,
    'delete_endpoints': delete_endpoints,
    'get_policy': get_policy,
    'get_device_violations': get_device_violations,
    'get_distribution_version': get_distribution_version,
    'create_distributions': create_distributions,
    'get_distribution_status': get_distribution_status,
    'get_distribution_url': get_distribution_url,
    'get_audit_management_log': get_audit_management_log,
    'get_audit_agent_report': get_audit_agent_report,
    'blacklist_files': blacklist_files,
    'whitelist_files': whitelist_files,
    'quarantine_files': quarantine_files,
    'get_quarantine_status': get_quarantine_status,
    'restore_file': restore_file,
    'retrieve_file': retrieve_file,
    'retrieve_file_details': retrieve_file_details,
    'xql_query': xql_query,
    'get_query_result_by_query_id': get_query_result_by_query_id,
    'get_alerts': get_alerts,
    'update_alerts': update_alerts,
    'insert_simple_indicators': insert_simple_indicators
}
