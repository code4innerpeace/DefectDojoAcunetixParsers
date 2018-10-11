import logging
import json
from dojo.models import Finding

logger = logging.getLogger(__name__)

__author__ = "Vijay Bheemineni"
__license__ = "MIT"
__version__ = "1.0.0"
__status__ = "Development"

class AcunetixScannerParser(object):
    """
        Acunetix Scanner Parser parses Acunetix JSON files.
    """
    def __init__(self, filename, test):
        self.data = json.load(filename)
        self.items = None
        self.create_findings(test)

    def create_findings(self, test):
        """
            This methods creates the findings objects.
        :param test: 
        :return: 
        """
        dupes = dict()

        for issue in self.data['issues']:
            title = issue['target_id'] + "_" + issue['vt_id'] + "_" + issue['vt_name'].replace(' ', '-')
            dupe_key = title + "_" + issue['vuln_id']
            url = issue['affects_url']
            severity = get_severity_text(issue['severity'])
            description = issue['description']
            mitigation = issue['recommendation']
            references = issue['references']
            impact = issue['impact']

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                find = None
                try:
                    find = Finding(
                        title=title,
                        url=url,
                        test=test,
                        severity=severity,
                        description=description,
                        mitigation=mitigation,
                        references=references,
                        impact=impact
                    )
                except Exception as e:
                    raise
                dupes[dupe_key] = find

        self.items = dupes.values()


def get_severity_text(severity):
    """
        This method returns severity information in text.
    :param severity: 
    :return: 
    """
    if severity == 0:
        return "Informational"
    elif severity == 1:
        return "Low"
    elif severity == 2:
        return "Medium"
    else:
        return "High"

if __name__ == "__main__":
    test = None
    filename = open('vas_test_scan.json', 'r')
    acunetix = AcunetixScannerParser(filename, test)
