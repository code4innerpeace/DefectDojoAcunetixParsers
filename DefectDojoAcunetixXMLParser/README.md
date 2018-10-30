# DefectDojo Acunetix XML Parser

DefectDojo XML parser parses the Acunetix vulnerability scanner using 'lxml' package. Currently, Acunetix XML Parser uses 'parse' method which reads the XML file and builds the XML tree in memory. 'parse' method should be good enough for small XML files but increases the memory usage when the XML file is very large. A better approach is to use 'iterparse' method which doesn't build the entire XML tree in memory. Due to the shortage of time, I had taken the first approach of using 'parse' method. But in future, I plan to implement Acunetix XML parser using 'iterparse' method.

#### Requirements

DefectDojo Acunetix XML Parser had written based on Acunetix XML report generated as of 10/29/2018. In the future, Acunetix may change XML report format.

##### Validate XML report downloaded by Acunetix Console by using 'validate_acunetix_scan_xml.py' utility script.

```
# Valid XML file which can be uploaded to DefectDojo.
$ python validate_acunetix_scan_xml.py
Acunetix Scan XML file 'vijay_valid_dummy_acunetix.xml' is valid. It can be uploaded to DefectDojo.

# Invalid XML file.
$ python validate_acunetix_scan_xml.py
Traceback (most recent call last):
  File "validate_acunetix_scan_xml.py", line 76, in <module>
    validate_acunetix_scan_xml_file(filename)
  File "validate_acunetix_scan_xml.py", line 57, in validate_acunetix_scan_xml_file
    scan_node = get_scan_node(root)
  File "validate_acunetix_scan_xml.py", line 45, in get_scan_node
    raise Exception(error_text)
Exception: ERROR: 'Scan' node must be first child of root element 'ScanGroup'.

```

#### Benchmarking

When I performed memory benchmarking on Acunetix XML file which contains 400-500 'ReportItems' the memory usage for building the tree in memory was around appx 250MB.  Below is the line which increases the memory usage by appx 220MB from appx 27MB. At this line, the XML tree is built in memory.

```
$ python -m memory_profiler parser_helper.py
247.6 MiB    220.8 MiB           tree = etree.parse(filename)
```

#### Code Coverage
Currently, my unit tests cover 86% of the code. Even though I had written test cases for most of the exceptions, code coverage shows these lines as not covered. I need to look into this issue. I want my unit test to cover 100% of the code.

```
$ coverage run parser_helper.py
$ coverage report --include parser_helper.py
Name               Stmts   Miss  Cover
--------------------------------------
parser_helper.py     103     14    86%
```

