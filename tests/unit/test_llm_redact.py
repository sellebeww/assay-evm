"""Redaction patterns and the allowlist of what may be sent."""

import os
from pathlib import Path

import pytest
from llm_support import FAKE_API_KEY, FAKE_BEARER_SECRET, FAKE_HEX_KEY, FAKE_MNEMONIC

from assay.llm import SourceNotAllowed, redact_text, scrub_secrets
from assay.llm.redact import (
    MAX_SNIPPET_LINES,
    check_relative_path,
    host_usernames,
    read_snippet,
    read_source,
)


def redact(text: str, usernames: tuple[str, ...] = ()) -> str:
    return redact_text(text, usernames=usernames).text


def test_private_key_block_is_removed() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIFAKEFAKEFAKE\nabcd\n-----END PRIVATE KEY-----"
    result = redact_text(f"before\n{pem}\nafter", usernames=())
    assert "MIIFAKE" not in result.text
    assert result.counts == {"private_key": 1}
    assert result.text.startswith("before\n")
    assert result.text.endswith("\nafter")


def test_truncated_private_key_block_is_removed_to_the_end() -> None:
    text = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFAKE"
    assert "MHcC" not in redact(text)


@pytest.mark.parametrize(
    "line",
    [
        f"uint256 privateKey = 0x{FAKE_HEX_KEY};",
        f'string pk = "{FAKE_HEX_KEY}";',
        f"vm.addr(0x{FAKE_HEX_KEY});",
        f"vm.startBroadcast({FAKE_HEX_KEY});",
        f"PRIVATE_KEY=0x{FAKE_HEX_KEY}",
    ],
)
def test_hex_private_keys_in_context_are_removed(line: str) -> None:
    assert FAKE_HEX_KEY not in redact(line)


def test_a_bare_bytes32_constant_is_kept() -> None:
    line = f"bytes32 constant ROLE = 0x{FAKE_HEX_KEY};"
    assert redact(line) == line


@pytest.mark.parametrize(
    "line",
    [
        f'string memory mnemonic = "{FAKE_MNEMONIC}";',
        f'string memory words = "{FAKE_MNEMONIC}";',
        f"seed phrase: {FAKE_MNEMONIC}",
    ],
)
def test_mnemonics_are_removed(line: str) -> None:
    result = redact_text(line, usernames=())
    assert "golf hotel" not in result.text
    assert result.counts.get("mnemonic") == 1


def test_an_ordinary_quoted_sentence_is_kept() -> None:
    line = 'revert("only the owner may call this");'
    assert redact(line) == line


@pytest.mark.parametrize(
    "text",
    [
        f"key = {FAKE_API_KEY}",
        "token ghp_" + "a1B2" * 9,
        "AKIA" + "ABCDEFGH12345678",
        "Authorization: Bearer " + FAKE_BEARER_SECRET,
        "eyJhbGciOiJI.eyJzdWIiOiJm.c2lnbmF0dXJl",
        f'string apiKey = "{FAKE_BEARER_SECRET}";',
        f"export SERVICE_API_TOKEN={FAKE_BEARER_SECRET}",
    ],
)
def test_api_key_formats_are_removed(text: str) -> None:
    result = redact_text(text, usernames=())
    assert result.counts.get("api_key") == 1
    assert "FAKE" not in result.text
    assert "ghp_" not in result.text
    assert "AKIA" not in result.text


def test_code_that_merely_mentions_tokens_is_kept() -> None:
    code = 'token = IERC20(_token); string public tokenName = "Wrapped Ether";'
    assert redact(code) == code


@pytest.mark.parametrize(
    "url",
    [
        "https://mainnet.example.org/v3/0123456789abcdef0123456789abcdef",
        "https://rpc.example.org/?apikey=abc",
        "https://rpc.example.org/path?token=abc&x=1",
        "https://user:pass@rpc.example.org/",
        "wss://rpc.example.org/ws/ABCDEFGHIJKLMNOPQRSTUVWX",
    ],
)
def test_rpc_urls_that_embed_a_token_are_removed(url: str) -> None:
    result = redact_text(f"rpc = {url} ;", usernames=())
    assert result.counts == {"rpc_url": 1}
    assert "example.org" not in result.text


def test_a_plain_documentation_url_is_kept() -> None:
    text = "// see https://eips.ethereum.org/EIPS/eip-4626 for details"
    assert redact(text) == text


@pytest.mark.parametrize(
    "path",
    [
        "/Users/someone/Documents/project/src/Vault.sol",
        "/home/someone/work/x.sol",
        "/private/var/folders/ab/cd/T/file.txt",
        "~/projects/vault/src/A.sol",
        "C:\\Users\\someone\\project\\A.sol",
        "file:///Users/someone/project/A.sol",
    ],
)
def test_absolute_paths_are_removed(path: str) -> None:
    result = redact_text(f"error in {path} at line 3", usernames=())
    assert result.counts.get("path") == 1
    assert "someone" not in result.text
    assert "Users" not in result.text


def test_relative_paths_and_slashes_in_prose_are_kept() -> None:
    text = "import {A} from './lib/A.sol'; // src/Vault.sol and/or the pool, 1/2 of the fee"
    assert redact(text) == text


def test_user_names_are_removed_as_whole_words() -> None:
    result = redact_text("author: jdoe wrote jdoes_helper", usernames=("jdoe", "ab"))
    assert result.text == "author: <user> wrote jdoes_helper"
    assert result.counts == {"username": 1}


def test_host_user_names_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USER", "environment_user")
    assert "environment_user" in host_usernames()


def test_email_addresses_are_removed() -> None:
    assert "@" not in redact("contact: dev.person+tag@example.org")


def test_redaction_is_idempotent_and_reports_counts_only() -> None:
    text = f"key = {FAKE_API_KEY}\n/Users/someone/x/y\nmail a@b.example\n"
    once = redact_text(text, usernames=("someone",))
    twice = redact_text(once.text, usernames=("someone",))
    assert twice.text == once.text
    assert twice.total == 0
    assert once.counts == {"api_key": 1, "email": 1, "path": 1}


def test_scrub_secrets_replaces_every_occurrence() -> None:
    assert scrub_secrets("a SECRET b SECRET", ["SECRET", ""]) == (
        "a [REDACTED:secret] b [REDACTED:secret]"
    )


# Allowlist


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "src/.env",
        "src/.hidden/A.sol",
        "foundry.toml",
        "src/foundry.toml",
        "remappings.txt",
        "src/A.txt",
        "src/A.SOL",
        "src/A.sol.bak",
        "test/A.t.sol",
        "script/Deploy.s.sol",
        "../src/A.sol",
        "src/../../etc/A.sol",
        "/etc/passwd.sol",
        "~/src/A.sol",
        "src\\A.sol",
        "src/./A.sol",
        "src",
        "",
        "srcx/A.sol",
    ],
)
def test_paths_outside_the_allowlist_are_refused(path: str) -> None:
    with pytest.raises(SourceNotAllowed):
        check_relative_path(path)


def test_scope_can_name_other_directories() -> None:
    assert check_relative_path("contracts/A.sol", ("contracts",)).as_posix() == "contracts/A.sol"
    with pytest.raises(SourceNotAllowed):
        check_relative_path("src/A.sol", ("contracts",))


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "A.sol").write_text(
        "// INTENTIONALLY VULNERABLE: test fixture, do not deploy\n"
        f"// key {FAKE_API_KEY}\ncontract A {{}}\n// at /Users/someone/x/y\n"
    )
    (root / "foundry.toml").write_text("[profile.default]\nffi = true\n")
    (root / ".env").write_text("SECRET=1\n")
    return root


def test_read_source_returns_redacted_text_and_a_relative_path(tmp_path: Path) -> None:
    source = read_source(_project(tmp_path), "src/A.sol", usernames=("someone",))
    assert source.path == "src/A.sol"
    assert FAKE_API_KEY not in source.text
    assert "/Users" not in source.text
    assert source.counts == {"api_key": 1, "path": 1}
    assert "contract A" in source.text


def test_read_source_refuses_config_and_env_files(tmp_path: Path) -> None:
    root = _project(tmp_path)
    for name in ("foundry.toml", ".env"):
        with pytest.raises(SourceNotAllowed):
            read_source(root, name)


def test_read_source_refuses_symlinks(tmp_path: Path) -> None:
    root = _project(tmp_path)
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}")
    (root / "src" / "Link.sol").symlink_to(outside)
    (root / "src" / "dir").symlink_to(tmp_path, target_is_directory=True)
    for name in ("src/Link.sol", "src/dir/outside.sol"):
        with pytest.raises(SourceNotAllowed, match="symbolic"):
            read_source(root, name)


def test_read_source_refuses_missing_large_and_binary_files(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "src" / "Big.sol").write_text("x" * (256 * 1024 + 1))
    (root / "src" / "Bin.sol").write_bytes(b"\xff\xfe\x00")
    for name in ("src/Missing.sol", "src/Big.sol", "src/Bin.sol"):
        with pytest.raises(SourceNotAllowed):
            read_source(root, name)
    assert os.path.isdir(root / "src")


def test_snippets_are_line_ranges_of_allowed_files(tmp_path: Path) -> None:
    root = _project(tmp_path)
    snippet = read_snippet(root, "src/A.sol", 3, 3)
    assert snippet.text == "contract A {}"
    with pytest.raises(SourceNotAllowed):
        read_snippet(root, "foundry.toml", 1, 1)
    with pytest.raises(SourceNotAllowed):
        read_snippet(root, "src/A.sol", 5, 4)
    with pytest.raises(SourceNotAllowed):
        read_snippet(root, "src/A.sol", 1, MAX_SNIPPET_LINES + 1)


def test_a_json_prompt_is_redacted_by_value_and_its_escapes_are_not_text() -> None:
    import json

    from assay.llm.redact import redact_message_text

    document = json.dumps(
        {"a": "report a:\n\tkeep this", "b": f"key {FAKE_API_KEY} in /Users/someone/x/y"},
        sort_keys=True,
        separators=(",", ":"),
    )
    result = redact_message_text(document, usernames=())
    data = json.loads(result.text)
    assert data["a"] == "report a:\n\tkeep this"
    assert FAKE_API_KEY not in result.text
    assert "/Users" not in result.text
    assert result.counts == {"api_key": 1, "path": 1}
    # the same text outside a JSON document is still read as text
    assert "C:\\Users\\x" not in redact_message_text("C:\\Users\\x\\y", usernames=()).text
