from unittest import TestCase
from unittest.mock import patch
from acunetix_json_report_generator import create_parser,\
                                           get_scan_url, \
                                           get_json_response, \
                                           get_acunetix_request_headers, \
                                           get_request_headers, \
                                           get_scan_session_id, \
                                           get_scan_vulnerabilities_url, \
                                           get_scan_vulnerabilities_ids, \
                                           get_vulnerability_url, \
                                           get_vulnerabilities_details, \
                                           get_scan_vulnerabilities_json_report
import requests
import json


class CommandLineTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        parser = create_parser()
        cls.parser = parser


class AcunetixJsonReportGenerator(CommandLineTestCase):

    def setUp(self):
        # Acunetix Server URL. Example "https://127.0.0.1:9443"
        self.acunetix_server_url = "<ACUNETIX_SERVER_URL>"
        # Acunetix Server Dummy URL. Used for testing 'request' api exceptions.
        self.acunetix_server_url_dummy = "<ACUNETIX_SERVER_URL_DUMMY>"
        # Acunetix API AUTH TOKEN code. We can get API AUTH TOKEN from
        # Acunetix Application --> Administrator --> Profile --> API KEY
        self.api_auth_token = "<API_AUTH_TOKEN>"
        # Acunetix API AUTH TOKEN Dummy. Used for testing 'request' api exceptions.
        self.api_auth_token_dummy = "123456789123456789123456789"
        # Acunetix Scan ID. In order to get 'Scan Id'. Curl url "<ACUNETIX_URL>/api/v1/scans"
        # and fetch 'scan_id' from JSON ouput.
        self.scan_id = "<SCAN_ID>"
        # Acunetix Scan ID Dummy. For testing unit tests cases.
        self.scan_id_dummy = "12345678-1234-1234-1234-123456789012"
        self.scan_url = get_scan_url(self.acunetix_server_url, self.scan_id)
        self.scan_url_dummy = get_scan_url(self.acunetix_server_url_dummy, self.scan_id_dummy)
        self.CONTENT_TYPE = "application/json"
        # If SSL Certificate is invalid, we can disable SSL warning by setting this
        # variable to True.
        #self.disable_ssl_warnings = True
        self.disable_ssl_warnings = False
        # Acunetix Scan Session ID. In order to get 'Scan Session Id'. Curl url "<ACUNETIX_URL>/api/v1/scans/<SCAN_ID>"
        # and fetch 'scan_session_id' from JSON ouput.
        self.scan_session_id = '<SCAN_SESSION_ID>'
        # Scan Vulnerability IDs. In order to get 'Scan Vulnerability Ids". Curl url
        # "<ACUNETIX_URL>/api/v1/scans/<SCAN_ID>/results/<SCAN_SESSION_ID>/vulnerabilities"
        # and fetch 'vuln_id' from JSON Output.
        self.scan_vulnerabilities_ids = [
                                            '1234567890123456789',
                                            '1234567890123456789',
                                            '1234567890123456789',
                                            '1234567890123456789',
                                            '1234567890123456789'
                                        ]
        self.scan_vulnerability_url = self.acunetix_server_url + "/api/v1/scans/" + \
                                      self.scan_id + "/results/" + self.scan_session_id + \
                                      "/vulnerabilities/" + self.scan_vulnerabilities_ids[0]

    def tearDown(self):
        self.acunetix_server_url = None
        self.acunetix_server_url_dummy = None
        self.api_auth_token = None
        self.api_auth_token_dummy = None
        self.scan_id = None
        self.scan_id_dummy = None
        self.scan_url = None
        self.scan_url_dummy = None
        self.CONTENT_TYPE = None
        self.disable_ssl_warnings = None
        self.scan_session_id = None
        self.scan_vulnerabilities_ids = None
        self.scan_vulnerability_url = None

    def test_main_with_empty_args(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args([])

    def test_main_with_args(self):
        args = self.parser.parse_args(['-U', 'https://localhost:9443', '-A', '1234', '-S', 'scan123'])
        self.assertEqual(args.acunetix_server_url, 'https://localhost:9443')
        self.assertEqual(args.api_auth_token, '1234')
        self.assertEqual(args.scan_id, 'scan123')
        self.assertEqual(args.disable_ssl_warnings, False)

    def test_main_with_disable_ssl_warnings(self):
        args = self.parser.parse_args(['--disable_ssl_warnings', '-U',
                                       'https://localhost:9443', '-A', '1234', '-S', 'scan123'])
        self.assertEqual(args.disable_ssl_warnings, True)

    def test_get_acunetix_request_headers(self):

        expected_headers = dict()
        expected_headers['X-Auth'] = self.api_auth_token
        expected_headers['Content-type'] = self.CONTENT_TYPE
        self.assertEqual(get_acunetix_request_headers(self.api_auth_token), expected_headers)

    def test_get_scan_url(self):
        test_url = self.acunetix_server_url_dummy + "/api/v1/scans/" + self.scan_id_dummy
        self.assertEqual(get_scan_url(self.acunetix_server_url_dummy, self.scan_id_dummy), test_url)

    def test_get_request_headers(self):
        expected_headers = requests.utils.default_headers()
        acunetix_headers = get_acunetix_request_headers(self.api_auth_token_dummy)
        expected_headers.update(acunetix_headers)
        self.assertEqual(get_request_headers(self.api_auth_token_dummy), expected_headers)

    @patch('requests.get')
    def test_scan_url_empty_get_json_response(self, get_mock):
        get_mock.side_effect = requests.exceptions.RequestException
        url = None
        try:
            get_json_response(url, self.api_auth_token_dummy, True)
        except requests.exceptions.RequestException as e:
            pass
        else:
            self.fail("URL empty exception test case failed.")

    @patch('requests.get')
    def test_scan_scan_url_invalid_get_json_response(self, get_mock):
        get_mock.side_effect = requests.exceptions.HTTPError
        try:
            get_json_response(self.scan_url_dummy, self.api_auth_token_dummy, True)
        except requests.exceptions.RequestException as e:
            pass
        else:
            self.fail("Scan URL invalid.")

    @patch('requests.get')
    def test_api_token_invalid_get_json_response(self, get_mock,):
        get_mock.side_effect = requests.exceptions.HTTPError
        try:
            get_json_response(self.scan_url_dummy, self.api_auth_token_dummy, True)
        except requests.exceptions.RequestException as e:
            pass
        else:
            self.fail("API Token invalid.")

    def test_scan_get_json_response(self):

        json_response = get_json_response(self.scan_url, self.api_auth_token, True)
        self.check_scan_json_reponse(json_response)

    def test_disable_ssl_warnings_false_scan_get_json_response(self):

        json_response = get_json_response(self.scan_url, self.api_auth_token, False)
        self.check_scan_json_reponse(json_response)

    def check_scan_json_reponse(self,json_response):
        expected_severity_info = 1
        expected_severity_low = 2
        expected_severity_medium = 2
        severity_info = json_response['current_session']['severity_counts']['info']
        severity_low = json_response['current_session']['severity_counts']['low']
        severity_medium = json_response['current_session']['severity_counts']['medium']

        self.assertEqual(json_response['scan_id'], self.scan_id)
        self.assertEqual(severity_info, expected_severity_info)
        self.assertEqual(severity_low, expected_severity_low)
        self.assertEqual(severity_medium, expected_severity_medium)

    def test_get_scan_session_id(self):
        json_response = get_json_response(self.scan_url, self.api_auth_token, self.disable_ssl_warnings)
        self.assertEqual(get_scan_session_id(json_response), self.scan_session_id)

    def test_get_scan_vulnerabilities_url(self):
        expected_scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        self.assertEqual(get_scan_vulnerabilities_url(self.scan_url,
                                                      self.scan_session_id), expected_scan_vulnerabilities_url)

    def test_scan_vulnerabilities_json_response(self):
        scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
                                                               api_auth_token=self.api_auth_token, disable_ssl_warnings=True)
        self.assertTrue('vulnerabilities' in scan_vulnerabilities_json_response.keys())

    def test_get_scan_vulnerabilities_ids(self):

        scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
                                                               api_auth_token=self.api_auth_token,
                                                               disable_ssl_warnings=True)
        self.assertEqual(get_scan_vulnerabilities_ids(scan_vulnerabilities_json_response),
                         self.scan_vulnerabilities_ids)

    def test_get_vulnerability_url(self):
        scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        vulnerability_id = self.scan_vulnerabilities_ids[0]
        scan_vulnerability_url = get_vulnerability_url(scan_vulnerabilities_url, vulnerability_id)
        self.assertEqual(scan_vulnerability_url, self.scan_vulnerability_url)

    def test_get_vulnerabilities_details(self):
        scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
                                                               api_auth_token=self.api_auth_token,
                                                               disable_ssl_warnings=True)
        scan_vulnerabilities_ids = get_scan_vulnerabilities_ids(scan_vulnerabilities_json_response)
        vulnerabilities_details = get_vulnerabilities_details(scan_vulnerabilities_url,
                                                              self.api_auth_token,
                                                              scan_vulnerabilities_ids,
                                                              True)
        vulnerability_detail_1 = vulnerabilities_details[0]
        self.assertEqual(len(vulnerabilities_details), 5)
        self.assertTrue('cvss_score' in vulnerability_detail_1.keys())

    def test_get_scan_vulnerabilities_json_report(self):
        scan_vulnerabilities_url = self.scan_url + "/results/" + self.scan_session_id + "/vulnerabilities"
        scan_vulnerabilities_json_response = get_json_response(url=scan_vulnerabilities_url,
                                                               api_auth_token=self.api_auth_token,
                                                               disable_ssl_warnings=True)
        scan_vulnerabilities_ids = get_scan_vulnerabilities_ids(scan_vulnerabilities_json_response)
        vulnerabilities_details = get_vulnerabilities_details(scan_vulnerabilities_url,
                                                            self.api_auth_token,
                                                            scan_vulnerabilities_ids,
                                                            True)
        json_response = get_json_response(self.scan_url, self.api_auth_token, True)
        scan_vulnerabilities_json_report = get_scan_vulnerabilities_json_report(json_response, vulnerabilities_details)

        scan_vulnerabilities = json.loads(scan_vulnerabilities_json_report)
        self.assertEqual(scan_vulnerabilities['scan_id'], self.scan_id)
        self.assertEqual(len(scan_vulnerabilities['issues']), 5)



