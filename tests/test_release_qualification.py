from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
qualification = importlib.import_module("release_qualification")
SOURCE = "a" * 40
WORKFLOWS = ROOT / ".github/workflows"
CALLED = {
    "actions": "lint-actions.yml",
    "markdown": "lint-markdown.yml",
    "python_lint": "lint-python.yml",
    "python_tests": "test-python.yml",
    "security": "security.yml",
}


def success() -> dict:
    return {
        name: {"result": "success", "outputs": {"passed": "true"}} for name in CALLED
    }


def test_all_checks_pass_for_exact_source(monkeypatch, capsys) -> None:
    monkeypatch.setenv("QUALIFICATION_NEEDS", json.dumps(success()))
    monkeypatch.setenv("GITHUB_SHA", SOURCE)
    assert qualification.main() == 0
    assert capsys.readouterr().out == f"passed=true\nsource_sha={SOURCE}\n"


@pytest.mark.parametrize("name", CALLED)
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "", None, True])
def test_any_non_success_blocks_even_with_passed_output(name, result) -> None:
    needs = success()
    needs[name]["result"] = result
    with pytest.raises(ValueError):
        qualification.validate(json.dumps(needs), SOURCE)


@pytest.mark.parametrize("name", CALLED)
@pytest.mark.parametrize("outputs", [{}, {"passed": "false"}, {"passed": True}, None])
def test_success_without_internal_confirmation_blocks(name, outputs) -> None:
    needs = success()
    needs[name]["outputs"] = outputs
    with pytest.raises(ValueError):
        qualification.validate(json.dumps(needs), SOURCE)


@pytest.mark.parametrize("name", CALLED)
def test_missing_check_blocks(name) -> None:
    needs = success()
    del needs[name]
    with pytest.raises(ValueError):
        qualification.validate(json.dumps(needs), SOURCE)


@pytest.mark.parametrize(
    "raw", ["", "null", "[]", "{}", '{"actions":{},"actions":{}}', "x" * 65537]
)
def test_malformed_receipts_emit_no_success(raw, monkeypatch, capsys) -> None:
    monkeypatch.setenv("QUALIFICATION_NEEDS", raw)
    monkeypatch.setenv("GITHUB_SHA", SOURCE)
    assert qualification.main() == 1
    assert not capsys.readouterr().out


@pytest.mark.parametrize("source", ["main", "HEAD", "", SOURCE + "\n", "b" * 39])
def test_source_must_be_full_immutable_identity(source) -> None:
    with pytest.raises(ValueError):
        qualification.validate(json.dumps(success()), source)


def test_release_graph_requires_full_checks_before_build_and_publish() -> None:
    workflow = (WORKFLOWS / "release.yml").read_text()
    jobs = {
        name: body
        for name, body in re.findall(
            r"^  ([a-z_]+):\n(.*?)(?=^  [a-z_]+:\n|\Z)",
            workflow,
            flags=re.MULTILINE | re.DOTALL,
        )
    }
    for name, filename in CALLED.items():
        assert f"uses: ./.github/workflows/{filename}" in jobs[name]
        assert "if:" not in jobs[name] and "secrets:" not in jobs[name]
        reusable = (WORKFLOWS / filename).read_text()
        for checkout in reusable.split("uses: actions/checkout@")[1:]:
            config = checkout.split("\n      - name:", 1)[0]
            assert "ref: ${{ github.sha }}" in config
            assert "persist-credentials: false" in config
        assert (
            "workflow_call:" in reusable
            and "value: ${{ jobs.ci_result.outputs.passed }}" in reusable
        )
        assert "contents: read" in reusable and ": write" not in reusable
    gate = jobs["qualification"]
    assert "needs: [actions, markdown, python_lint, python_tests, security]" in gate
    assert (
        "if: always()" in gate and "QUALIFICATION_NEEDS: ${{ toJSON(needs) }}" in gate
    )
    assert '[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]]' in gate
    assert "python3 -I scripts/release_qualification.py" in gate
    assert "needs: qualification" in jobs["verify"]
    assert "needs: [verify, qualification]" in jobs["publish"]
    for name in ("verify", "publish"):
        assert re.search(r"^    if:", jobs[name], re.MULTILINE) is None
    assert "continue-on-error" not in workflow
    assert "docker build" not in gate
    assert workflow.count("docker build ") == 2
    for name in (*CALLED, "qualification", "verify"):
        assert ": write" not in jobs[name]
    for name in ("verify", "publish"):
        body = jobs[name]
        assert '[[ "$source_sha" == "$GITHUB_SHA" ]]' in body
        assert '[[ "$QUALIFIED" == true && "$QUALIFIED_SHA" == "$GITHUB_SHA" ]]' in body
        assert 'git --no-replace-objects cat-file tag "$tag_object_sha"' in body
        assert "python3 -I scripts/verify_release_signature.py" in body
    publisher = jobs["publish"]
    assert '[[ "$tag_object_sha" == "$EXPECTED_TAG_OBJECT_SHA" ]]' in publisher
    assert (
        "EXPECTED_TAG_OBJECT_SHA: ${{ needs.verify.outputs.tag_object_sha }}"
        in publisher
    )
    assert publisher.index("verify_release_signature.py") < publisher.index(
        "docker login"
    )
    assert jobs["verify"].index("verify_release_signature.py") < jobs["verify"].index(
        "docker build"
    )


FAKE_TOOLS = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
if tool == 'gh':
    obj = {'type': 'tag', 'sha': os.environ['TAG_SHA']}
    if '/git/ref/' in args[-1]:
        print(json.dumps({'ref': 'refs/tags/v1.2.3', 'object': obj}))
    else:
        print(json.dumps({'tag': 'v1.2.3', 'sha': obj['sha'],
            'object': {'type': 'commit', 'sha': os.environ['API_SOURCE']},
            'verification': {'verified': True, 'reason': 'valid'}}))
elif tool == 'git':
    if args[:3] == ['--no-replace-objects', 'cat-file', 'tag']:
        sys.stdout.buffer.write(Path(os.environ['RAW_TAG']).read_bytes())
    elif args == ['rev-parse', 'HEAD']:
        print(os.environ['CHECKOUT_SHA'])
    elif args[0] == 'merge-base':
        sys.exit(1 if os.environ['DAMAGE'] == 'off-main' else 0)
    elif args[0] not in ('cat-file', 'fetch'):
        sys.exit(99)
elif tool == 'gpg':
    if '--verify' in args:
        if os.environ['DAMAGE'] == 'bad-signature':
            sys.exit(1)
        fingerprint = '02EBB31CC0032A86C2C0401A1534542E61DC82D3'
        if os.environ['DAMAGE'] == 'other-signer':
            fingerprint = 'A' * 40
        print('[GNUPG:] NEWSIG')
        print('[GNUPG:] GOODSIG ' + fingerprint[-16:] + ' Synthetic')
        print('[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-09-18 1789689600 0 4 0 1 10 00 ' + fingerprint)
"""


@pytest.mark.parametrize(
    "step_name",
    [
        "Verify approved signed annotated tag",
        "Independently verify the signed tag and source",
    ],
)
@pytest.mark.parametrize(
    "damage",
    [
        "none",
        "unqualified",
        "qualified-source",
        "source",
        "checkout",
        "object",
        "off-main",
        "bad-signature",
        "other-signer",
    ],
)
def test_actual_release_authorization_steps_fail_before_next_stage(
    tmp_path, monkeypatch, step_name, damage
) -> None:
    # Exercise the actual shell boundary with synthetic API/Git/GPG interfaces;
    # separate signature tests exercise real GnuPG cryptography.
    raw = (
        f"object {SOURCE}\ntype commit\ntag v1.2.3\ntagger Synthetic\n\nRelease\n"
        "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n"
    ).encode()
    raw_path = tmp_path / "raw-tag"
    raw_path.write_bytes(raw)
    tag_sha = hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    values = {
        "DAMAGE": damage,
        "TAG_SHA": tag_sha,
        "RAW_TAG": str(raw_path),
        "API_SOURCE": SOURCE,
        "GITHUB_SHA": SOURCE,
        "CHECKOUT_SHA": SOURCE,
        "QUALIFIED": "true",
        "QUALIFIED_SHA": SOURCE,
        "RELEASE_TAG": "v1.2.3",
        "PRERELEASE": "false",
        "EXPECTED_TAG_OBJECT_SHA": tag_sha,
        "ARTIFACT_ID": "123",
        "GITHUB_REPOSITORY": "lloydsmart/unifi-cert-renewer",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }
    key = {
        "unqualified": "QUALIFIED",
        "qualified-source": "QUALIFIED_SHA",
        "source": "API_SOURCE",
        "checkout": "CHECKOUT_SHA",
        "object": "TAG_SHA",
    }.get(damage)
    if key:
        values[key] = "false" if key == "QUALIFIED" else "b" * 40
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    binary = tmp_path / "bin"
    binary.mkdir()
    for name in ("gh", "git", "gpg"):
        script = binary / name
        script.write_text(FAKE_TOOLS)
        script.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary) + os.pathsep + os.environ["PATH"])
    workflow = (WORKFLOWS / "release.yml").read_text()
    step = workflow.split(f"      - name: {step_name}\n", 1)[1]
    step = step.split("\n      - name:", 1)[0]
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    script += '\nprintf eligible >"$RUNNER_TEMP/next-stage"\n'
    result = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, capture_output=True, timeout=20
    )
    assert (result.returncode == 0) == (damage == "none"), result.stderr
    assert (tmp_path / "next-stage").exists() == (damage == "none")
