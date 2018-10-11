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
2) git clone repo.
```
cd /tmp
git clone https://github.com/code4innerpeace/DefectDojoAcunetixParsers.git
```
2) cd 'DefectDojo' repo and copy 'acunetix' folder 'tools' directory.
```
cd DefectDojoAcunetixParsers/DefectDojoAcunetixJsonParser/
cp -r acunetix <DefectDojoRepo>/django-DefectDojo/dojo/tools/
```
3) Update [factory.py](https://github.com/DefectDojo/djangoDefectDojo/blob/master/dojo/tools/factory.py "factory.py") file.

```
cp factory.py factory.py.org

### Add below lines to the 'factory.py' file.
# Below line above __author__ = 'Jay Paz'
from dojo.tools.acunetix.parser import AcunetixScannerParser

# Below above else:
elif scan_type == 'Acunetix Scan':
        parser = AcunetixScannerParser(file, test)
```
4) Add 'Acunetix' scanner to 'SCAN_TYPE_CHOICES' variable in Update [forms.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/forms.py#L251 "forms.py") file. <span style="color:red">*The value being added to 'SCAN_TYPE_CHOICES' variable, should match 'scan_type' in step 3.*</span>
```
cp <DefectDojoRepo>/django-DefectDojo/dojo/forms.py <DefectDojoRepo>/django-DefectDojo/dojo/forms.py.org

# Add below line to 'SCAN_TYPE_CHOICES' variable. Also make there is ','. All scanners are separated by a ','.
("Acunetix Scan", "Acunetix Scan")
```

5) Add the new scanner to the [Template](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/templates/dojo/import_scan_results.html#L27 "import_scan_results.html").

```
cd <DefectDojoRepo>/django-DefectDojo/dojo/templates/dojo
cp import_scan_results.html import_scan_results.html.org

# Add below line in 'Unordered List' block after line 28.
<li><b>Acunetix Scanner</b> - JSON format.</li>
```

6) Add the new importer to the [test type]https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/fixtures/test_type.json "test_type.json") for new installations.<span style="color:red">*Make sure 'pk' value of the scanner is unique.*</span>

```
cd <DefectDojoRepo>/django-DefectDojo/dojo/fixtures
cp test_type.json test_type.json.org

# Add below lines to the JSON array. 
{
    "fields": {
      "name": "Acunetix Scan"
    },
    "model": "dojo.test_type",
    "pk": 33
  }
```
#### Known Issues

<b>Issue 1:- If you get below exception. Make sure 'Admin' User profile info is update with email id and other details.</b>

Traceback (most recent call last):
  File "/usr/local/lib/python2.7/dist-packages/django/core/handlers/exception.py", line 41, in inner
    response = get_response(request)
  File "/usr/local/lib/python2.7/dist-packages/django/core/handlers/base.py", line 249, in _legacy_get_response
    response = self._get_response(request)
  File "/usr/local/lib/python2.7/dist-packages/django/core/handlers/base.py", line 187, in _get_response
    response = self.process_exception_by_middleware(e, request)
  File "/usr/local/lib/python2.7/dist-packages/django/core/handlers/base.py", line 185, in _get_response
    response = wrapped_callback(request, *callback_args, **callback_kwargs)
  File "/usr/local/lib/python2.7/dist-packages/django/contrib/auth/decorators.py", line 23, in _wrapped_view
    return view_func(request, *args, **kwargs)
  File "/defectdojo/django-DefectDojo/dojo/engagement/views.py", line 541, in import_scan_results
    item.save(dedupe_option=False)
  File "/defectdojo/django-DefectDojo/dojo/models.py", line 1213, in save
    if self.reporter.usercontactinfo.block_execution:
  File "/usr/local/lib/python2.7/dist-packages/django/utils/functional.py", line 239, in inner
    return func(self._wrapped, *args)
  File "/usr/local/lib/python2.7/dist-packages/django/db/models/fields/related_descriptors.py", line 407, in __get__
    self.related.get_accessor_name()
RelatedObjectDoesNotExist: User has no usercontactinfo.
