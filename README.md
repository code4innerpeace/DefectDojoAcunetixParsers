# DefectDojo Acunetix Parser

[DefectDojo](https://github.com/DefectDojo "Github Repo") is an open source vulnerability management tool. 'DefectDojo' parser utility allows to import XML or JSON vulnerabilities report into 'DefectDojo' application. List of 'Parsers' supported by 'DefectDojo' can be found at <https://github.com/DefectDojo/django-DefectDojo/tree/master/dojo/tools>.

Acunetix is one of the leading 'Web Vulnerability Scanner' but as of today 'DefectDojo' doesn't have the parser to import vulnerability report from Acunetix. Also currently Acunetix vulnerability scanner doesn't allow to export vulnerabilities list in JSON format. Python script [acunetix_json_report_generator.py](https://github.com/code4innerpeace/DefectDojoAcunetixParsers/blob/master/AcunetixJsonReportGenerator/acunetix_json_report_generator.py "acunetix_json_report_generator.py") dumps scan vulnerabilities details into JSON file and DefectDojo [parser](https://github.com/code4innerpeace/DefectDojoAcunetixParsers/blob/master/DefectDojoAcunetixJsonParser/acunetix/parser.py "parser") imports JSON file created by [acunetix_json_report_generator.py](https://github.com/code4innerpeace/DefectDojoAcunetixParsers/blob/master/AcunetixJsonReportGenerator/acunetix_json_report_generator.py "acunetix_json_report_generator.py") into DefectDojo.<span style="color:red">*Since Acunetix officially doesn't allow to export vulnerabilities in JSON format, I can't push Acunetix parser to 'DefectDojo' official repo. So I am sharing the code in my github repo.*</span>

## Requirements
[acunetix_json_report_generator.py](https://github.com/code4innerpeace/DefectDojoAcunetixParsers/blob/master/AcunetixJsonReportGenerator/acunetix_json_report_generator.py "acunetix_json_report_generator.py") :- Implemented and tested on Python 3.6

[parser](https://github.com/code4innerpeace/DefectDojoAcunetixParsers/blob/master/DefectDojoAcunetixJsonParser/acunetix/parser.py "parser") :- Implemented and tested on Python 2.7 which is required by DefectDojo application.


## Steps to import Acunetix Scan Vulnerabilities into DefectDojo

#### Create Acunetix JSON Report( For XML, download vulnerabilities XML report from Acunetix Console. ) 

1) git pull <https://github.com/code4innerpeace/DefectDojoAcunetixParsers>
2) cd DefectDojoAcunetixParsers/AcunetixJsonReportGenerator
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

#### Implement the Acunetix JSON or XML Parser in DefectDojo

1) Log onto DefectDojo server.
2) git clone repo.
```
cd /tmp
git clone https://github.com/code4innerpeace/DefectDojoAcunetixParsers.git
```
3) cd 'DefectDojo' repo and copy 'acunetix' folder 'tools' directory. For JSON follow JSON parser steps and for XML follow XML parser steps.

##### JSON Parser
```
cd DefectDojoAcunetixParsers/DefectDojoAcunetixXMLParser/
cp -r acunetix <DefectDojoRepo>/django-DefectDojo/dojo/tools/
```

##### XML Parser
```
cd DefectDojoAcunetixParsers/DefectDojoAcunetixJsonParser/
cp -r acunetix <DefectDojoRepo>/django-DefectDojo/dojo/tools/
```
4) Update [factory.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/tools/factory.py "factory.py") file.

```
cp factory.py factory.py.org

### Add below lines to the 'factory.py' file.
# Below line above __author__ = 'Jay Paz'
from dojo.tools.acunetix.parser import AcunetixScannerParser

# Below above else:
elif scan_type == 'Acunetix Scan':
        parser = AcunetixScannerParser(file, test)
```
5) Add 'Acunetix' scanner to 'SCAN_TYPE_CHOICES' variable in Update [forms.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/forms.py#L251 "forms.py") file. <span style="color:red">*The value being added to 'SCAN_TYPE_CHOICES' variable, should match 'scan_type' in step 3.*</span>
```
cp <DefectDojoRepo>/django-DefectDojo/dojo/forms.py <DefectDojoRepo>/django-DefectDojo/dojo/forms.py.org

# Add below line to 'SCAN_TYPE_CHOICES' variable. Also make there is ','. All scanners are separated by a ','.
("Acunetix Scan", "Acunetix Scan")
```

6) Add the new scanner to the [Template](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/templates/dojo/import_scan_results.html#L27 "import_scan_results.html").

##### JSON Parser
```
cd <DefectDojoRepo>/django-DefectDojo/dojo/templates/dojo
cp import_scan_results.html import_scan_results.html.org

# Add below line in 'Unordered List' block after line 28.
<li><b>Acunetix Scanner</b> - JSON format.</li>
```
##### XML Parser
```
cd <DefectDojoRepo>/django-DefectDojo/dojo/templates/dojo
cp import_scan_results.html import_scan_results.html.org

# Add below line in 'Unordered List' block after line 28.
<li><b>Acunetix Scanner</b> - XML format.</li>
```

7) Add the new importer to the [test type](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/fixtures/test_type.json "test_type.json") for new installations.<span style="color:red">*Make sure 'pk' value of the scanner is unique.*</span>

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
#### Testing

I was able to import Acunetix JSON report with appx 400 vulnerabilities without any issue into DefectDojo.

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

<b>Issue 2:- When 'dynamic_finding' field in 'Finding' is set to 'True'. I am receiving below exception from Django code. I need to analyze further why this is happening. As of now 'dynamic_finding' had been set to 'False' in 'parser_models.py' file. </b>

Internal Server Error: /engagement/88/import_scan_results

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

  File "/defectdojo/django-DefectDojo/dojo/engagement/views.py", line 555, in import_scan_results

    item.save(dedupe_option=False)

  File "/defectdojo/django-DefectDojo/dojo/models.py", line 1185, in save

    self.hash_code = self.compute_hash_code()

  File "/defectdojo/django-DefectDojo/dojo/models.py", line 1049, in compute_hash_code

    for e in self.endpoints.all():

  File "/usr/local/lib/python2.7/dist-packages/django/db/models/fields/related_descriptors.py", line 513, in __get__

    return self.related_manager_cls(instance)

  File "/usr/local/lib/python2.7/dist-packages/django/db/models/fields/related_descriptors.py", line 830, in __init__

    (instance, self.pk_field_names[self.source_field_name]))

ValueError: "<Finding: VijayTest_VijayTest.com_CWE-56_/scoring/.DS_Store>" needs to have a value for field "id" before this many-to-many relationship can be used.

Internal Server Error: /engagement/88/import_scan_results

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

  File "/defectdojo/django-DefectDojo/dojo/engagement/views.py", line 555, in import_scan_results

    item.save(dedupe_option=False)

  File "/defectdojo/django-DefectDojo/dojo/models.py", line 1185, in save

    self.hash_code = self.compute_hash_code()

  File "/defectdojo/django-DefectDojo/dojo/models.py", line 1049, in compute_hash_code

    for e in self.endpoints.all():

  File "/usr/local/lib/python2.7/dist-packages/django/db/models/fields/related_descriptors.py", line 513, in __get__

    return self.related_manager_cls(instance)

  File "/usr/local/lib/python2.7/dist-packages/django/db/models/fields/related_descriptors.py", line 830, in __init__

    (instance, self.pk_field_names[self.source_field_name]))

ValueError: "<Finding: VijayTest_VijayTest.com_CWE-56_/scoring/.DS_Store>" needs to have a value for field "id" before this many-to-many relationship can be used.


