from nextgenmap.paths import resource_path


def test_resource_path_resolves_bootstrap():
    path = resource_path("nmap-bootstrap.xsl")
    assert path.exists()
    assert path.name == "nmap-bootstrap.xsl"
