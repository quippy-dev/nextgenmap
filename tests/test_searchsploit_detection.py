from pathlib import Path

from nextgenmap import searchsploit


def _make_executable(path: Path):
    path.write_text("", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_detect_searchsploit_prefers_env_path(monkeypatch, tmp_path):
    env_binary = _make_executable(tmp_path / "searchsploit-env")
    monkeypatch.setenv("SEARCHSPLOIT_PATH", str(env_binary))
    monkeypatch.setenv("PATH", "")

    program, args = searchsploit.detect_searchsploit_binary()

    assert program == str(env_binary)
    assert args == []


def test_detect_searchsploit_from_path(monkeypatch, tmp_path):
    monkeypatch.delenv("SEARCHSPLOIT_PATH", raising=False)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path_binary = _make_executable(bin_dir / "searchsploit")
    monkeypatch.setenv("PATH", str(bin_dir))

    program, args = searchsploit.detect_searchsploit_binary()

    assert program == str(path_binary)
    assert args == []


def test_detect_searchsploit_brew_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setenv("PATH", "")
    brew_binary = _make_executable(tmp_path / "brew-searchsploit")
    monkeypatch.setattr(searchsploit, "BREW_SEARCHSPLOIT_PATHS", [str(brew_binary)])

    program, args = searchsploit.detect_searchsploit_binary()

    assert program == str(brew_binary)
    assert args == []


def test_detect_searchsploit_wsl_fallback(monkeypatch):
    monkeypatch.delenv("SEARCHSPLOIT_PATH", raising=False)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(searchsploit.sys, "platform", "win32")
    monkeypatch.setattr(searchsploit, "BREW_SEARCHSPLOIT_PATHS", [])

    def fake_which(cmd):
        if cmd in ("searchsploit", "searchsploit.exe"):
            return None
        if cmd == "wsl":
            return "wsl"
        return None

    monkeypatch.setattr(searchsploit.shutil, "which", fake_which)

    program, args = searchsploit.detect_searchsploit_binary()

    assert program == "wsl"
    assert args == ["-e", "searchsploit"]


def test_build_searchsploit_command_appends_args(monkeypatch, tmp_path):
    env_binary = _make_executable(tmp_path / "searchsploit-env")
    monkeypatch.setenv("SEARCHSPLOIT_PATH", str(env_binary))
    monkeypatch.setenv("PATH", "")

    program, args = searchsploit.build_searchsploit_command("http service")

    assert program == str(env_binary)
    assert args[-3:] == ["-t", "http service", "-j"]
