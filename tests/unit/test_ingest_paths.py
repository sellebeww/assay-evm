import pytest

from assay.ingest import UnsafePathError, safe_relative_path


@pytest.mark.parametrize(
    "path",
    [
        "a",
        "src/Counter.sol",
        "lib/forge-std/src/Test.sol",
        ".github/workflows/ci.yml",
        "dir with space/x.sol",
        "ünïcode/Ñame.sol",
        "...",
        "a..b/c",
    ],
)
def test_safe_paths_are_accepted(path: str) -> None:
    assert str(safe_relative_path(path)) == path


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("", "empty path"),
        ("/etc/passwd", "absolute path"),
        ("//server/share", "absolute path"),
        ("..", "path traversal"),
        ("../x", "path traversal"),
        ("src/../../x", "path traversal"),
        ("src/..", "path traversal"),
        ("a//b", "empty or '.' path component"),
        ("./a", "empty or '.' path component"),
        ("a/.", "empty or '.' path component"),
        ("a/", "empty or '.' path component"),
        ("a\\..\\b", "backslash in path"),
        ("a\nb", "control character in path"),
        ("a\x00b", "control character in path"),
        ("a\x1b[31m", "control character in path"),
        ("\udc80.sol", "path is not valid UTF-8"),
    ],
)
def test_unsafe_paths_are_rejected(path: str, reason: str) -> None:
    with pytest.raises(UnsafePathError) as info:
        safe_relative_path(path)
    assert info.value.reason == reason
    assert info.value.path == path
