""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
  
import requests
import time
import datetime
from connectors.core.connector import get_logger, ConnectorError
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
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, method='GET', endpoint=None, params=None, data=None,
                      json=None, flag=False):
        if endpoint:
            url = '{0}{1}'.format(self.server_url, endpoint)
        else:
            url = '{0}'.format(self.server_url)

        logger.info('Request URL {}'.format(url))
        headers = {"x-xdr-auth-id": str(self.api_key_id), "Authorization": self.api_key, "Content-Type": "application/json"}
        try:
            response = requests.request(method=method, url=url, params=params, data=data, json=json,
                                        headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                result = response.json()
                if result.get('error'):
                    raise ConnectorError('{}'.format(result.get('error').get('message')))
                if response.status_code == 204:
                    return {"Status": "Success", "Message": "Executed successfully"}
                return result
            elif messages_codes[response.status_code]:
                logger.error('{}'.format(messages_codes[response.status_code]))
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


def handle_list_parameter(key, value, result):
    if not isinstance(value, list):
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
            filters_dict['value'] = v
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


def fetch_incidents(config, params):
    try:
        obj = CortexXdr(config)
        if not (params.get('incident_id_list') or params.get('alert_sources') or params.get(
                'description') or params.get('modification_time') or params.get('creation_time')):
            raise ConnectorError(
                'At least one of the [Incident ID List, Alert Sources, Description, Modification Time, Creation Time] is required.')
        endpoint = '/incidents/get_incidents/'
        result = build_payload(params)
        filters_list = []
        keys = ["incident_id_list", "alert_sources", "description", "modification_time", "creation_time"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('incident_id_list'):
                handle_list_parameter('incident_id_list', str(params.get('incident_id_list')), result)
            if result.get('alert_sources'):
                handle_list_parameter('alert_sources', params.get('alert_sources'), result)
            if result.get('sort'):
                sortby = [{
                    "field": sort_field.get(result.get('field')),
                    "keyword": sort_order.get(result.get('keyword'))
                }]
                result['sort'] = sortby
                result.pop('field')
                result.pop('keyword')
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"search_from": result.get('search_from')})
            payload.get('request_data').update({"search_to": result.get('search_to')})
            payload.get('request_data').update({"sort": result.get('sort')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_incident_details(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/incidents/get_incident_extra_data/'
        payload = {
            "request_data": {
                "incident_id": params.get('incident_id')
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
                "incident_id": params.get('incident_id'),
                "update_data": {}
            }
        }
        if result:
            if result.get('manual_severity'):
                result['manual_severity'] = severity_mapping.get(result.get('manual_severity'))
                # result.pop('manual_severity')
            if result.get('status'):
                result['status'] = status_mapping.get(result.get('status'))
                # result.pop('status')
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
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
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
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def isolate_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/isolate/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {}
        }
        if result.get('isolate_endpoint') == 'Isolate One Endpoint':
            payload.get('request_data').update({"endpoint_id": result.get('endpoint_id')})
            return obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        elif result.get('isolate_endpoint') == 'Isolate More Than One Endpoint':
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
            return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def unisolate_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/unisolate/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result.get('unisolate_endpoint') == 'Unisolate One Endpoint':
            payload.get('request_data').update({"endpoint_id": result.get('endpoint_id')})
            return obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        elif result.get('unisolate_endpoint') == 'Unisolate More Than One Endpoint':
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
            return response
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
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            if result.get('sort'):
                sortby = [{
                    "field": sort_field.get(result.get('field')),
                    "keyword": sort_order.get(result.get('keyword'))
                }]
                result['sort'] = sortby
                result.pop('field')
                result.pop('keyword')
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"search_from": result.get('search_from')})
            payload.get('request_data').update({"search_to": result.get('search_to')})
            payload.get('request_data').update({"sort": result.get('sort')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def scan_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/scan/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def cancel_scan_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/abort_scan/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def delete_endpoints(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/delete/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
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
        if not (params.get('endpoint_id_list') or params.get('vendor') or params.get(
                'vendor_id') or params.get('product') or params.get('product_id') or params.get('serial') or params.get(
            'hostname') or params.get('username') or params.get('type') or params.get('ip_list') or params.get(
            'violation_id_list') or params.get('timestamp')):
            raise ConnectorError(
                'At least one of the [Endpoint ID List, Vendor, Vendor ID, Product, Product ID, Serial, Hostname, Username, Type, IP List, Violation ID List, timestamp] is required.')
        endpoint = '/device_control/get_violations/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "vendor", "vendor_id", "product", "product_id", "serial", "hostname", "username",
                "type", "ip_list", "violation_id_list", "timestamp"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('vendor'):
                handle_list_parameter('vendor', params.get('vendor'), result)
            if result.get('vendor_id'):
                handle_list_parameter('vendor_id', params.get('vendor_id'), result)
            if result.get('product'):
                handle_list_parameter('product', params.get('product'), result)
            if result.get('product_id'):
                handle_list_parameter('product_id', params.get('product_id'), result)
            if result.get('serial'):
                handle_list_parameter('serial', params.get('serial'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('username'):
                handle_list_parameter('username', params.get('username'), result)
            if result.get('type'):
                result['type'] = violation_type.get(result.get('type'))
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('violation_id_list'):
                handle_list_parameter('violation_id_list', params.get('violation_id_list'), result)
            if result.get('timestamp'):
                build_timestamp('timestamp', result.get('timestamp'), result)
            if result.get('sort'):
                sortby = [{
                    "field": sort_field.get(result.get('field')),
                    "keyword": sort_order.get(result.get('keyword'))
                }]
                result['sort'] = sortby
                result.pop('field')
                result.pop('keyword')
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"search_from": result.get('search_from')})
            payload.get('request_data').update({"search_to": result.get('search_to')})
            payload.get('request_data').update({"sort": result.get('sort')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
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
        result = build_payload(params)
        filters_list = []
        keys = ["email", "type", "sub_type", "result", "timestamp"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('email'):
                handle_list_parameter('email', params.get('email'), result)
            if result.get('type'):
                handle_list_parameter('type', params.get('type'), result)
            if result.get('sub_type'):
                handle_list_parameter('sub_type', params.get('sub_type'), result)
            if result.get('result'):
                handle_list_parameter('result', params.get('result'), result)
            if result.get('timestamp'):
                build_timestamp('timestamp', result.get('timestamp'), result)
            if result.get('sort'):
                sortby = [{
                    "field": "timestamp",
                    "keyword": sort_order.get(result.get('keyword'))
                }]
                result['sort'] = sortby
                result.pop('field')
                result.pop('keyword')
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"search_from": result.get('search_from')})
            payload.get('request_data').update({"search_to": result.get('search_to')})
            payload.get('request_data').update({"sort": result.get('sort')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def get_audit_agent_report(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/audits/agents_reports/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id", "endpoint_name", "type", "sub_type", "result", "domain", "xdr_version", "category",
                "timestamp"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id'):
                handle_list_parameter('endpoint_id', params.get('endpoint_id'), result)
            if result.get('endpoint_name'):
                handle_list_parameter('endpoint_name', params.get('endpoint_name'), result)
            if result.get('type'):
                handle_list_parameter('type', params.get('type'), result)
            if result.get('sub_type'):
                handle_list_parameter('sub_type', params.get('sub_type'), result)
            if result.get('result'):
                handle_list_parameter('result', params.get('result'), result)
            if result.get('domain'):
                handle_list_parameter('domain', params.get('domain'), result)
            if result.get('xdr_version'):
                handle_list_parameter('xdr_version', params.get('xdr_version'), result)
            if result.get('category'):
                result['category'] = category_mapping.get(result.get('category'))
            if result.get('timestamp'):
                build_timestamp('timestamp', result.get('timestamp'), result)
            if result.get('sort'):
                sortby = [{
                    "field": sort_field.get(result.get('field')),
                    "keyword": sort_order.get(result.get('keyword'))
                }]
                result['sort'] = sortby
                result.pop('field')
                result.pop('keyword')
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"search_from": result.get('search_from')})
            payload.get('request_data').update({"search_to": result.get('search_to')})
            payload.get('request_data').update({"sort": result.get('sort')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def blacklist_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/hash_exceptions/blacklist/'
        payload = {
            "request_data": {
            }
        }
        if not isinstance(params.get('hash_list'), list):
            alerts = [x.strip() for x in params.get('hash_list').split(',')]
            payload.get('request_data').update({"hash_list": alerts})
        if params.get('comment'):
            payload.get('request_data').update({"comment": params.get('comment')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def whitelist_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/hash_exceptions/whitelist/'
        payload = {
            "request_data": {
            }
        }
        if not isinstance(params.get('hash_list'), list):
            alerts = [x.strip() for x in params.get('hash_list').split(',')]
            payload.get('request_data').update({"hash_list": alerts})
        if params.get('comment'):
            payload.get('request_data').update({"comment": params.get('comment')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def quarantine_files(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/quarantine/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            payload.get('request_data').update({"file_path": result.get('file_path')})
            payload.get('request_data').update({"file_hash": result.get('file_hash')})
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
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
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
        raise ConnectorError(Err)


def retrieve_file(config, params):
    try:
        obj = CortexXdr(config)
        endpoint = '/endpoints/file_retrieval/'
        result = build_payload(params)
        filters_list = []
        keys = ["endpoint_id_list", "dist_name", "group_name", "alias", "hostname", "ip_list", "platform", "isolate",
                "first_seen", "last_seen"]
        payload = {
            "request_data": {
            }
        }
        if result:
            if result.get('endpoint_id_list'):
                handle_list_parameter('endpoint_id_list', params.get('endpoint_id_list'), result)
            if result.get('dist_name'):
                handle_list_parameter('dist_name', params.get('dist_name'), result)
            if result.get('group_name'):
                handle_list_parameter('group_name', params.get('group_name'), result)
            if result.get('alias'):
                handle_list_parameter('alias', params.get('alias'), result)
            if result.get('hostname'):
                handle_list_parameter('hostname', params.get('hostname'), result)
            if result.get('ip_list'):
                handle_list_parameter('ip_list', params.get('ip_list'), result)
            if result.get('platform'):
                result['platform'] = platform_mapping.get(result.get('platform'))
            if result.get('isolate'):
                result['isolate'] = isolate_mapping.get(result.get('isolate'))
            if result.get('first_seen'):
                build_timestamp('first_seen', result.get('first_seen'), result)
            if result.get('last_seen'):
                build_timestamp('last_seen', result.get('last_seen'), result)
            build_filter_payload(result, keys, filters_list)
            payload.get('request_data').update({"filters": filters_list})
            if not isinstance(result.get('file_path'), list):
                file_paths = [x.strip() for x in params.get('file_path').split(',')]
                files = {"file": {
                    platform_mapping.get(result.get('files')): file_paths
                }
                }
            else:
                files = {"file": {
                    platform_mapping.get(result.get('files')): result.get('file_path')
                }
                }
            payload.get('request_data').update(files)
        response = obj.make_api_call(method='POST', endpoint=endpoint, json=payload)
        return response
    except Exception as Err:
        logger.error('Exception occurred: {}'.format(Err))
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
    'retrieve_file': retrieve_file
}
