# DefectDojo Acunetix Parser

[DefectDojo](https://github.com/DefectDojo "Github Repo") is an open source vulnerability management tool. DefectDojo has parsers utility which allows to import vulnerabilities scan XML or JSON report into 'DefectDojo'. Currently supported 'Parsers' can be found at this link <https://github.com/DefectDojo/django-DefectDojo/tree/master/dojo/tools>.

As of today 'DefectDojo' doesn't have parser to import utility from 'Acunetix'. So I had written 'Parser' to import 'Acunetix' scan vulnerability output into 'DefectDojo'. Acunetix currently doesn't provide 'JSON' ouput, I had written an utility 'acunetix_json_report_generator' to generate scan vulnerability in JSON format. <span style="color:red">*Since Acunetix officially doesn't provide JSON output, I can't push my Acunetix parser to 'DefectDojo' official repo. So I am sharing the code in my repo.*</span>

## Steps to import Acunetix Scan Vulnerabilities into DefectDojo

#### Create Acunetix JSON Report

1) git pull <repo>
2) cd AcunetixJsonReportGenerator
3) ```python acunetix_json_report_generator.py -h```
4) Creating the report 
```
python acunetix_json_report_generator.py -U <ACUNETIX_SERVER_URL> -A <ACUNETIX_API_AUTH_TOKEN> -S <ACUNETIX_SCAN_ID> --disable_ssl_warnings --output_file_name=<REPORT_FILE_NAME>
```

<b>ACUNETIX_SERVER_URL</b> :- Acunetix Server URL

<b>ACUNETIX_API_AUTH_TOKEN</b> :- We can get API AUTH TOKEN from by logging into Acunetix Application --> Administrator --> Profile --> API KEY

<b>ACUNETIX_SCAN_ID</b> :- In order to get 'Scan Id'. Curl url "<ACUNETIX_URL>/api/v1/scans" and fetch 'scan_id' from JSON ouput. Below is the sample CURL command to fetch the 'scan_id>

```
curl -k --request GET --url "<ACUNETIX_SERVER_URL>/api/v1/scans" --header "X-Auth: <ACUNETIX_API_TOKEN>" --header "Content-type: application/json" | jq .scans[].scan_id
```

#### Implementing the Acunetix JSON Parser in DefectDojo 

1) Log onto DefectDojo server.
2) cd 'DefectDojo' repo.
3) cd dojo/tools
4) copy 'acunetix' parser folder downloaded from this repo into 'dojo/tools' directory.
