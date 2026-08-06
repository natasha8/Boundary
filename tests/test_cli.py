from pytest import CaptureFixture

from boundary.cli import main


def test_cli_displays_help_without_arguments(
    capsys: CaptureFixture[str],
) -> None:
    main([])

    output = capsys.readouterr().out

    assert output.startswith("usage: boundary")
    assert "Evidence-driven Web and API security scanner." in output
