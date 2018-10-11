import json
import requests
import argparse
import logging
import urllib3


logging.basicConfig(level=logging.ERROR)

CONTENT_TYPE = "application/json"
ACUNETIX_API_URI = "/api/v1"
scan_vulnerability_report = dict()
urllib3.disable_warnings()


def create_parser():
    """
        This method creates runtime argument parser.
    :return: parser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-U', '--acunetix_server_url', help='Acunetix Server URL', type=str, required=True)
    parser.add_argument('-A', '--api_auth_token', help='Acunetix API Authentication Token', type=str, required=True)
    parser.add_argument('-S', '--scan_id', help='Acunetix Scan ID', type=str, required=True)
    parser.add_argument('--output_file_name', help='Acunetix JSON Scan Report Filename', type=str, required=False,
                        default='scan_report.json')
    parser.add_argument('--disable_ssl_warnings', help='Disable SSL Certificate warnings', action='store_true',
                        required=False)
    return parser


def get_acunetix_request_headers(api_auth_token):
    """
        This method returns headers required by Acunetix API.
    :param api_auth_token: 
    :return: acunetix_headers
    """
    acunetix_headers = dict()
    acunetix_headers['X-Auth'] = api_auth_token
    acunetix_headers['Content-type'] = CONTENT_TYPE
    return acunetix_headers


def get_scan_url(acunetix_server_url, scan_id):
    """
        This method return the scan_id url.
    :param acunetix_server_url: 
    :param scan_id: 
    :return: acunetix_scan_url
    """
    scan_url = acunetix_server_url + ACUNETIX_API_URI + "/scans/" + scan_id
    return scan_url


def get_request_headers(api_auth_token):
    """
        This method returns request headers required by 'requests' api.
    :param api_auth_token: 
    :return: headers
    """
    headers = requests.utils.default_headers()
    acunetix_headers = get_acunetix_request_headers(api_auth_token)
    headers.update(acunetix_headers)
    return headers


def get_json_response(url, api_auth_token, disable_ssl_warnings):
    """
        This method returns json response for acunetix api url provided.
    :param url: 
    :param api_auth_token: 
    :param disable_ssl_warnings: 
    :return: json response
    """
    headers = get_request_headers(api_auth_token)
    try:
        response = None

        if disable_ssl_warnings:
            response = requests.get(url, headers=headers, verify=False)
        else:
            response = requests.get(url, headers=headers)

        response.raise_for_status()
        decode_response = response.content.decode('utf-8')
        json_response = json.loads(decode_response)
        return json_response
    except requests.exceptions.HTTPError as he:
        logging.error("Error: {he}".format(he=he))
        raise he
    except requests.exceptions.ConnectionError as ce:
        logging.error("Error: {ce}".format(ce=ce))
        raise ce
    except requests.exceptions.Timeout as t:
        logging.error("Error: {t}".format(t=t))
        raise t
    except requests.exceptions.RequestException as re:
        logging.error("Error: Fetching response from the {url} .".format(url=url))
        raise re


def get_scan_vulnerabilities_json_response(url, api_auth_token, disable_ssl_warnings):
    """
        This method returns scan vulnerabilities details in json format.
    :param url: 
    :param api_auth_token: 
    :param disable_ssl_warnings: 
    :return: scan_vulnerabilities_json_response
    """
    cursor = 0
    vulnerabilities_details = []
    scan_vulnerabilities_json_response = dict()

    while True:
        cursor_url = url + "?c=" + str(cursor)
        json_response = get_json_response(cursor_url, api_auth_token, disable_ssl_warnings)
        [vulnerabilities_details.append(vulnerability) for vulnerability in json_response['vulnerabilities']]
        cursor = json_response['pagination']['next_cursor']
        if not cursor:
            break

    scan_vulnerabilities_json_response['vulnerabilities'] = vulnerabilities_details
    return scan_vulnerabilities_json_response


def get_scan_session_id(json_response):
    """
        This method return scan session id for scan id provided.
    :param json_response: 
    :return: scan_session_id
    """
    return json_response['current_session']['scan_session_id']


def get_scan_vulnerabilities_url(scan_url, scan_session_id):
    """
        This method returns scan vulnerabilities url. 
        This is the url which returns all vulnerabilities for particular scan.
    :param scan_url: 
    :param scan_session_id: 
    :return: scan_vulnerabilities_url
    """
    scan_vulnerabilities_url = scan_url + "/results/" + scan_session_id + "/vulnerabilities"
    return scan_vulnerabilities_url


def get_scan_vulnerabilities_ids(scan_vulnerabilities_json_response):
    """
        This method provides scan vulnerabilities ids.
    :param scan_vulnerabilities_json_response: 
    :return: scan_vulnerabilities_ids
    """
    scan_vulnerabilities_ids = [i['vuln_id'] for i in scan_vulnerabilities_json_response['vulnerabilities']]
    return scan_vulnerabilities_ids


def get_vulnerability_url(scan_vulnerabilities_url, vulnerability_id):
    """
        This method provides scan vulnerability url. This is the url for particular vulnerability.
    :param scan_vulnerabilities_url: 
    :param vulnerability_id: 
    :return: vulnerability_url
    """
    return scan_vulnerabilities_url + "/" + vulnerability_id


def get_vulnerabilities_details(scan_vulnerabilities_url, api_auth_token, scan_vulnerabilities_ids,
                                disable_ssl_warnings):
    """
        This method returns array of vulnerabilities json details.
    :param scan_vulnerabilities_url: 
    :param api_auth_token: 
    :param scan_vulnerabilities_ids: 
    :param disable_ssl_warnings: 
    :return: vulnerabilities_details
    """
    vulnerabilities_details = []
    for vulnerability_id in scan_vulnerabilities_ids:
        vulnerability_url = get_vulnerability_url(scan_vulnerabilities_url, vulnerability_id)
        json_response = get_json_response(vulnerability_url, api_auth_token, disable_ssl_warnings)
        vulnerabilities_details.append(json_response)
    return vulnerabilities_details


def get_scan_vulnerabilities_json_report(json_response, vulnerabilities_details):
    """
        This returns scan vulnerabilities in json format.
    :param json_response: 
    :param vulnerabilities_details: 
    :return: scan_vulnerabilities_json_report
    """
    scan_vulnerability_details = dict()
    scan_vulnerability_details['scan_id'] = json_response['scan_id']
    scan_vulnerability_details['scan_criticality'] = json_response['criticality']
    scan_vulnerability_details['scan_start_date'] = json_response['current_session']['start_date']
    scan_vulnerability_details['scan_profile_name'] = json_response['profile_name']
    scan_vulnerability_details['scan_target_address'] = json_response['target']['address']
    scan_vulnerability_details['scan_target_id'] = json_response['target_id']
    scan_vulnerability_details['issues'] = vulnerabilities_details
    scan_vulnerabilities_json_report = json.dumps(scan_vulnerability_details)
    return scan_vulnerabilities_json_report


def create_scan_vulnerabilities_json_report(acunetix_server_url, api_auth_token, scan_id, disable_ssl_warnings,
                                            output_file_name):
    """
        This method creates the scan vulnerabilities json file.
    :param acunetix_server_url: 
    :param api_auth_token: 
    :param scan_id: 
    :param disable_ssl_warnings: 
    :param output_file_name: 
    :return: 
    """
    json_response = None
    scan_vulnerabilities_json_response = None
    scan_url = get_scan_url(acunetix_server_url=acunetix_server_url, scan_id=scan_id)
    logging.info("INFO : Scan URL : {scan_url}\n".format(scan_url=scan_url))

    if disable_ssl_warnings:
        json_response = get_json_response(url=scan_url, api_auth_token=api_auth_token, disable_ssl_warnings=True)
    else:
        json_response = get_json_response(url=scan_url, api_auth_token=api_auth_token, disable_ssl_warnings=False)

    scan_session_id = get_scan_session_id(json_response)
    logging.info("INFO : Scan session ID : {scan_session_id}\n".format(scan_session_id=scan_session_id))

    scan_vulnerabilities_url = get_scan_vulnerabilities_url(scan_url, scan_session_id)
    logging.info("INFO : Scan vulnerabilities URL : {scan_vulnerabilities_url}\n".
                 format(scan_vulnerabilities_url=scan_vulnerabilities_url))

    if disable_ssl_warnings:
        # scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
        #                                                      api_auth_token=api_auth_token, disable_ssl_warnings=True)
        scan_vulnerabilities_json_response = get_scan_vulnerabilities_json_response(
                                                                                    url=scan_vulnerabilities_url,
                                                                                    api_auth_token=api_auth_token,
                                                                                    disable_ssl_warnings=True
                                                                                    )
    else:
        # scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
        #                                                     api_auth_token=api_auth_token, disable_ssl_warnings=False)
        scan_vulnerabilities_json_response = get_scan_vulnerabilities_json_response(
                                                                                    url=scan_vulnerabilities_url,
                                                                                    api_auth_token=api_auth_token,
                                                                                    disable_ssl_warnings=False
                                                                                    )
    logging.info("INFO : Scan vulnerabilities JSON response : {scan_vulnerabilities_json_response}\n".
                 format(scan_vulnerabilities_json_response=scan_vulnerabilities_json_response))

    scan_vulnerabilities_ids = get_scan_vulnerabilities_ids(scan_vulnerabilities_json_response)
    vulnerabilities_details = get_vulnerabilities_details(scan_vulnerabilities_url, api_auth_token,
                                                          scan_vulnerabilities_ids, disable_ssl_warnings)
    scan_vulnerabilities_json_report = get_scan_vulnerabilities_json_report(json_response, vulnerabilities_details)
    scan_vulnerabilities_json_report_dict = json.loads(scan_vulnerabilities_json_report)
    logging.info("INFO : Scan vulnerabilities JSON report Dict : {scan_vulnerabilities_json_report_dict}\n".
                 format(scan_vulnerabilities_json_report_dict=scan_vulnerabilities_json_report_dict))

    with open(output_file_name, 'w') as outfile:
        json.dump(scan_vulnerabilities_json_report_dict, outfile)
        print("INFO : Scan vulnerabilities json report file : {output_file_name} has been created successfully.".
              format(output_file_name=output_file_name))


def main():
    parser = create_parser()
    args = parser.parse_args()
    create_scan_vulnerabilities_json_report(args.acunetix_server_url, args.api_auth_token, args.scan_id,
                                            args.disable_ssl_warnings, args.output_file_name)


if __name__ == "__main__":
    main()
