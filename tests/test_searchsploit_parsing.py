import xml.etree.ElementTree as ET

from nextgenmap.searchsploit import get_services_to_search, process_searchsploit_results


def test_get_services_to_search_collects_products():
    xml = """
    <nmaprun>
      <host>
        <address addr="10.0.0.1" />
        <ports>
          <port>
            <service product="Apache" version="2.4.57" />
          </port>
          <port>
            <service product="OpenSSH" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    root = ET.fromstring(xml)

    services = get_services_to_search(root)

    assert services["10.0.0.1"] == {"apache 2.4.57", "openssh"}


def test_process_searchsploit_results_extracts_fields():
    payload = {
        "RESULTS_EXPLOIT": [
            {
                "Type": "remote",
                "Title": "Sample Exploit",
                "Path": "exploits/sample.txt",
                "EDB-ID": "12345",
                "Date_Published": "2024-01-01",
                "Date_Updated": "2024-01-02",
                "Platform": "Linux",
                "Author": "Researcher",
                "Port": "80",
                "Verified": "True",
                "Codes": "CVE-2024-0001",
                "Application": "Apache",
                "Source": "ExploitDB",
            }
        ]
    }

    results = process_searchsploit_results(payload, "10.0.0.1")

    assert results[0]["host"] == "10.0.0.1"
    assert results[0]["title"] == "Sample Exploit"
    assert results[0]["type"] == "exploit (remote)"
