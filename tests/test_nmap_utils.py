from nextgenmap.nmap_utils import custom_split, remove_argument, strip_output_flags


def test_custom_split_keeps_quoted_arg():
    cmd = 'nmap --script "default or (discovery and safe)" scanme.nmap.org'
    parts = custom_split(cmd)
    assert parts[0] == "nmap"
    assert "--script" in parts
    assert any("default or (discovery and safe)" in part for part in parts)


def test_remove_argument_removes_following_value():
    args = ["-p", "80,443", "-sV", "scanme.nmap.org"]
    assert remove_argument(args, "-p") == ["-sV", "scanme.nmap.org"]


def test_strip_output_flags():
    args = ["-sV", "-oX", "out.xml", "-oA", "base", "-p", "80"]
    assert strip_output_flags(args) == ["-sV", "-p", "80"]
