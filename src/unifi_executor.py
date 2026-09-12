"""Executor that runs only inside the UniFi key-owning environment.

Production access is provided by the fixed local Unix-socket service in
``unifi_executor_service``. Live TLS itself remains application-side; this module
only durably finalises its exact pending transaction. Tests substitute private
platform primitives against disposable files only.
"""

import fcntl
import hashlib
import os
import pwd
import re
import threading
import uuid
from contextlib import contextmanager

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from secure_file import open_secure_file
from unifi_client import (
    MAX_CERTIFICATE_DER_BYTES,
    MAX_KEYTOOL_OUTPUT_CHARS,
    CertificateImportRequest,
    CertificatePolicy,
    PublicKeystoreState,
    UnifiOperationError,
    build_unifi_csr_command,
    inspect_public_keystore_state,
    parse_keytool_metadata,
    prepare_certificate_import,
    validate_requested_csr,
    verify_certificate_import,
)
from unifi_executor_files import (
    CANONICAL,
    JOURNAL,
    JOURNAL_NEW,
    LOCK,
    ROLLBACK,
    STAGE,
    _Files,
)
from unifi_process import _run, _Service

_PHASES = {
    "quiescing",
    "quiesced",
    "staging",
    "staged_validated",
    "rollback_durable",
    "commit_possible",
    "committed",
    "canonical_verified",
    "service_resumed_pending_live_verification",
    "live_verified",
    "recovery_required",
    "recovered_old",
}


def _password_environment():
    with open_secure_file(
        "unifi-keystore-password", source_name="UniFi password", require_private=True
    ) as stream:
        data = stream.read(4097)
    if not 1 <= len(data) <= 4096:
        raise UnifiOperationError("invalid UniFi password file")
    value = data.decode("utf-8").removesuffix("\n")
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise UnifiOperationError("invalid UniFi password file")
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "UNIFI_KEYSTORE_PASSWORD": value}


def _public_id(state):
    info = inspect_public_keystore_state(state)
    return {
        "spki": info.certificate.spki_sha256,
        "chain": [
            hashlib.sha256(der).hexdigest() for der in state.certificate_chain_der
        ],
    }


def _inode(info):
    return [info.st_dev, info.st_ino]


def _same_public(first, second):
    return (
        inspect_public_keystore_state(first) == inspect_public_keystore_state(second)
        and first.certificate_chain_der == second.certificate_chain_der
    )


def _parse_collection(data: bytes) -> PublicKeystoreState:
    if not isinstance(data, bytes) or len(data) > MAX_KEYTOOL_OUTPUT_CHARS:
        raise UnifiOperationError("public collection exceeds limit")
    text = data.decode("utf-8")
    # Full -list -rfc provides global type/provider plus every alias's chain in
    # one keytool read. Isolate exactly one alias; never return raw diagnostics.
    sections = re.split(r"(?m)^Alias name: ", text)
    matches = [part for part in sections[1:] if part.splitlines()[0] == "unifi"]
    if len(matches) != 1:
        raise UnifiOperationError("expected alias is missing or duplicated")
    selected = sections[0] + "Alias name: " + matches[0]
    store, alias = parse_keytool_metadata(selected)
    blocks = []
    current = None
    for line in selected.splitlines():
        line = line.strip()
        if line == "-----BEGIN CERTIFICATE-----":
            if current is not None:
                raise UnifiOperationError("nested public certificate block")
            current = [line]
        elif line == "-----END CERTIFICATE-----":
            if current is None:
                raise UnifiOperationError("unexpected public certificate terminator")
            current.append(line)
            blocks.append("\n".join(current).encode("ascii"))
            current = None
        elif current is not None:
            if re.fullmatch(r"[A-Za-z0-9+/=]{1,128}", line) is None:
                raise UnifiOperationError("invalid public certificate encoding")
            current.append(line)
    if current is not None:
        raise UnifiOperationError("unterminated public certificate block")
    if not 1 <= len(blocks) <= 10:
        raise UnifiOperationError("invalid public certificate collection")
    chain = tuple(
        x509.load_pem_x509_certificate(block).public_bytes(Encoding.DER)
        for block in blocks
    )
    output = (
        f"Keystore type: {store.keystore_type}\n"
        f"Keystore provider: {store.provider}\nAlias name: {alias.alias_name}\n"
        f"Entry type: {alias.entry_type}\n"
        f"Certificate chain length: {alias.certificate_chain_length}\n"
    )
    state = PublicKeystoreState(output, chain)
    inspect_public_keystore_state(state)
    return state


def _validate_journal(value):
    fields = {
        "version",
        "transaction",
        "phase",
        "resume",
        "old",
        "issued",
        "old_inode",
        "stage_inode",
        "rollback_expected",
        "commit_possible",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise UnifiOperationError("invalid recovery journal")
    if (
        type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["transaction"], str)
        or re.fullmatch(r"[0-9a-f]{32}", value["transaction"]) is None
        or not isinstance(value["phase"], str)
        or value["phase"] not in _PHASES
    ):
        raise UnifiOperationError("invalid recovery journal")
    for key in ("resume", "rollback_expected", "commit_possible"):
        if type(value[key]) is not bool:
            raise UnifiOperationError("invalid recovery journal")
    for key in ("old", "issued"):
        identity = value[key]
        if key == "issued" and identity is None:
            continue
        if (
            not isinstance(identity, dict)
            or set(identity) != {"spki", "chain"}
            or not isinstance(identity["chain"], list)
            or not 1 <= len(identity["chain"]) <= 10
        ):
            raise UnifiOperationError("invalid journal public identity")
        for digest in [identity["spki"], *identity["chain"]]:
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise UnifiOperationError("invalid journal public identity")
    for key in ("old_inode", "stage_inode"):
        identity = value[key]
        if key == "stage_inode" and identity is None:
            continue
        if (
            not isinstance(identity, list)
            or len(identity) != 2
            or any(type(n) is not int or n < 0 for n in identity)
        ):
            raise UnifiOperationError("invalid journal file identity")
    if value["commit_possible"] and (
        value["issued"] is None
        or value["stage_inode"] is None
        or not value["rollback_expected"]
    ):
        raise UnifiOperationError("inconsistent recovery journal")
    if value["phase"] == "live_verified" and (
        not value["resume"]
        or not value["rollback_expected"]
        or not value["commit_possible"]
        or value["issued"] is None
        or value["stage_inode"] is None
        or value["old_inode"] == value["stage_inode"]
        or value["old"]["spki"] != value["issued"]["spki"]
        or len(value["issued"]["chain"]) != 2
    ):
        raise UnifiOperationError("inconsistent live-verified journal")
    return value


def _local_identity():
    if os.geteuid() != 0:
        raise UnifiOperationError("key-owner executor requires local root")
    abc = pwd.getpwnam("abc")
    if (abc.pw_uid, abc.pw_gid) != (1000, 1000):
        raise UnifiOperationError("unreviewed UniFi ownership baseline")
    return abc.pw_uid, abc.pw_gid


class ProductionUnifiExecutor:
    """Only instantiate in the key-owning container, never in the renewer.

    No caller supplies a path, executable, argv, alias, service name, or secret.
    """

    def __init__(self):
        self._files = None
        self._lock = None
        self._owner = None
        self._journal = None
        self._service = None
        self._expect_stopped = False

    @contextmanager
    def _locked(self):
        if self._lock is not None:
            raise UnifiOperationError("executor already active")
        files = None
        lock = None
        try:
            files = _Files(*_local_identity())
            if not files.exists(LOCK):
                try:
                    with files.opened(LOCK, create=True):
                        pass
                    files.sync_directory()
                except FileExistsError:
                    pass
            lock = os.open(
                LOCK,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=files.fd,
            )
            expected = files.status(LOCK)
            if _inode(os.fstat(lock)) != _inode(expected):
                raise UnifiOperationError("executor lock replaced")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._files, self._lock = files, lock
            self._expect_stopped = False
            self._owner = threading.get_ident()
            self._service = _Service(lock)
            self._service.no_keytool()
            yield
        except Exception:
            raise UnifiOperationError(
                "UniFi executor operation failed; recovery may be required"
            ) from None
        finally:
            safe_to_release = True
            if self._service is not None:
                try:
                    self._service.no_keytool()
                    if self._expect_stopped:
                        self._service.stopped()
                except BaseException:
                    safe_to_release = False
            if safe_to_release:
                self._files = self._lock = self._owner = self._service = None
                self._journal = None
                # Never LOCK_UN: children share this open-file-description lock.
                if lock is not None:
                    os.close(lock)
                if files is not None:
                    files.close()
            else:
                # Deliberately retain descriptors until this helper exits. A
                # surviving/uninspectable writer requires operator intervention.
                raise UnifiOperationError(
                    "writer survives; executor lock retained"
                ) from None

    def _assert_locked(self):
        if self._lock is None or self._owner != threading.get_ident():
            raise UnifiOperationError("exclusive executor context required")

    def _collect(self, name):
        self._assert_locked()
        if name not in {CANONICAL, STAGE, ROLLBACK}:
            raise UnifiOperationError("invalid collection target")
        before = self._files.status(name)
        # Dirfd-anchored path avoids ancestor substitution during execution.
        # The fixed command refers to the parent's open directory descriptor.
        data = self._keytool(name, "-list", "-rfc")
        self._files.same(name, before)
        return _parse_collection(data)

    def _keytool(self, name, *operation, data=b""):
        self._assert_locked()
        if name not in {CANONICAL, STAGE, ROLLBACK}:
            raise UnifiOperationError("invalid keytool target")
        if "-importcert" in operation and name != STAGE:
            raise UnifiOperationError("canonical keytool mutation prohibited")
        # /proc/<parent>/fd holds the already-open trusted directory. On parent
        # death, an already-running Java child may fail, but cannot hit canonical.
        path = f"/proc/{os.getpid()}/fd/{self._files.fd}/{name}"
        argv = (
            "/usr/bin/keytool",
            "-J-Duser.language=en",
            "-J-Duser.country=US",
            *operation,
            "-keystore",
            path,
            "-storetype",
            "PKCS12",
            "-storepass:env",
            "UNIFI_KEYSTORE_PASSWORD",
        )
        return _run(argv, data, _password_environment(), self._lock)

    def _no_transaction(self):
        if any(
            self._files.exists(name) for name in (JOURNAL, JOURNAL_NEW, STAGE, ROLLBACK)
        ):
            raise UnifiOperationError("recovery required before another operation")

    def inspect_public_state(self) -> PublicKeystoreState:
        if self._lock is not None:
            self._assert_locked()
            return self._collect(CANONICAL)
        with self._locked():
            self._no_transaction()
            return self._collect(CANONICAL)

    def generate_csr(self, policy: CertificatePolicy) -> bytes:
        command = build_unifi_csr_command(policy)
        with self._locked():
            self._no_transaction()
            before = self._files.status(CANONICAL)
            state = self._collect(CANONICAL)
            if _public_id(state)["spki"] != policy.expected_spki_sha256.lower():
                raise UnifiOperationError("CSR baseline differs from current key")
            # Reconstruct only semantic CSR fields from the validated builder.
            # The caller cannot pass an argv or select the keystore/password name.
            result = self._keytool(
                CANONICAL,
                "-certreq",
                "-alias",
                "unifi",
                "-keypass:env",
                "UNIFI_KEYSTORE_PASSWORD",
                "-dname",
                command[command.index("-dname") + 1],
                "-ext",
                command[command.index("-ext") + 1],
                "-rfc",
                "-sigalg",
                "SHA384withRSA",
            )
            self._files.same(CANONICAL, before)
            validate_requested_csr(result, policy)
            return result

    def _phase(self, phase, **changes):
        self._journal = {**self._journal, **changes, "phase": phase}
        _validate_journal(self._journal)
        self._files.write_journal(self._journal)

    def _resume_service(self, *, startup=False):
        self._service.stopped()
        before = self._files.status(CANONICAL)
        public = _public_id(self._collect(CANONICAL))
        if self._journal["resume"] and not startup:
            self._service.start()
            self._expect_stopped = False
        self._files.same(CANONICAL, before)
        if _public_id(self._collect(CANONICAL)) != public:
            raise UnifiOperationError("canonical changed while restoring service")

    @contextmanager
    def exclusive(self):
        with self._locked():
            self._no_transaction()
            before = self._collect(CANONICAL)
            identity = self._files.status(CANONICAL)
            if identity.st_nlink != 1:
                raise UnifiOperationError("unexpected canonical hard link")
            self._journal = {
                "version": 1,
                "transaction": uuid.uuid4().hex,
                "phase": "quiescing",
                "resume": self._service.running(),
                "old": _public_id(before),
                "issued": None,
                "old_inode": _inode(identity),
                "stage_inode": None,
                "rollback_expected": False,
                "commit_possible": False,
            }
            self._phase("quiescing")  # Durable intent BEFORE s6 -d.
            try:
                self._expect_stopped = True
                self._service.stop()
                self._files.same(CANONICAL, identity)
                if not _same_public(self._collect(CANONICAL), before):
                    raise UnifiOperationError("canonical changed while quiescing")
                self._phase("quiesced")
                yield
                self._service.stopped()
                if self._journal["phase"] != "canonical_verified":
                    raise UnifiOperationError("transaction did not verify canonical")
                if (
                    _public_id(self._collect(CANONICAL)) != self._journal["issued"]
                    or _inode(self._files.status(CANONICAL))
                    != self._journal["stage_inode"]
                ):
                    raise UnifiOperationError("canonical changed before service resume")
                self._resume_service()
                self._phase("service_resumed_pending_live_verification")
            except BaseException:
                # No implicit rollback or retry. A separate recover() starts
                # with fresh state and restores service only after proving safety.
                self._phase("recovery_required")
                raise

    def import_certificate_reply(
        self, request: CertificateImportRequest, *, expected_before: PublicKeystoreState
    ) -> int:
        self._assert_locked()
        if self._journal is None or self._journal["phase"] != "quiesced":
            raise UnifiOperationError("new quiesced transaction required")
        plan = prepare_certificate_import(request)
        self._service.stopped()
        current = self._collect(CANONICAL)
        if not _same_public(current, request.before) or not _same_public(
            current, expected_before
        ):
            raise UnifiOperationError("stale public import request")
        old = self._files.status(CANONICAL)
        if (
            _inode(old) != self._journal["old_inode"]
            or _public_id(current) != self._journal["old"]
        ):
            raise UnifiOperationError("canonical differs from journal")
        issued = {
            "spki": plan.issued.spki_sha256,
            "chain": [
                hashlib.sha256(der).hexdigest() for der in plan.certificate_chain_der
            ],
        }
        self._phase("staging", issued=issued)
        self._files.copy_stage()
        stage = self._files.status(STAGE)
        self._phase("staging", stage_inode=_inode(stage))
        if not _same_public(self._collect(STAGE), current):
            raise UnifiOperationError("stage differs before import")
        self._keytool(
            STAGE,
            "-importcert",
            "-alias",
            "unifi",
            "-noprompt",
            "-keypass:env",
            "UNIFI_KEYSTORE_PASSWORD",
            data=plan.reply_pem,
        )
        if _inode(self._files.status(STAGE)) != _inode(stage):
            raise UnifiOperationError("stage inode replaced during import")
        verify_certificate_import(self._collect(STAGE), request)
        validated = self._files.status(STAGE)
        self._files.sync_file(STAGE)
        self._phase("staged_validated")
        self._service.stopped()
        self._files.same(CANONICAL, old)
        if not _same_public(self._collect(CANONICAL), current):
            raise UnifiOperationError("canonical changed during staging")
        self._files.same(CANONICAL, old)
        self._files.sync_file(CANONICAL)
        self._files.link_rollback()
        rollback = self._files.status(ROLLBACK)
        if _inode(rollback) != _inode(old):
            raise UnifiOperationError("rollback inode differs")
        self._files.sync_directory()
        self._phase("rollback_durable", rollback_expected=True)
        self._phase("commit_possible", commit_possible=True)
        self._service.stopped()
        self._files.same(CANONICAL, rollback)
        self._files.same(STAGE, validated)
        self._files.replace(STAGE, CANONICAL)
        self._files.sync_directory()
        self._phase("committed")
        if _inode(self._files.status(CANONICAL)) != _inode(stage):
            raise UnifiOperationError("committed inode differs")
        verify_certificate_import(self._collect(CANONICAL), request)
        self._phase("canonical_verified")
        return 0

    def finalize_live_verification(self, expected_leaf_der: bytes) -> str:
        """Durably accept exact live evidence, then remove recovery artifacts.

        The leaf fingerprint is not an authorization token: it must identify the
        already-pending issued chain in the executor-owned journal. There is no
        Boolean success input and no caller-selected transaction or pathname.
        """

        if (
            not isinstance(expected_leaf_der, bytes)
            or not 1 <= len(expected_leaf_der) <= MAX_CERTIFICATE_DER_BYTES
        ):
            raise UnifiOperationError("invalid live certificate evidence")
        try:
            canonical = x509.load_der_x509_certificate(expected_leaf_der).public_bytes(
                Encoding.DER
            )
        except ValueError:
            raise UnifiOperationError("invalid live certificate evidence") from None
        if canonical != expected_leaf_der:
            raise UnifiOperationError("non-canonical live certificate evidence")
        fingerprint = hashlib.sha256(canonical).hexdigest()

        with self._locked():
            if not self._files.exists(JOURNAL):
                raise UnifiOperationError("no pending transaction to finalise")
            self._journal = _validate_journal(self._files.read_journal())
            if self._journal["phase"] not in {
                "service_resumed_pending_live_verification",
                "live_verified",
            }:
                raise UnifiOperationError(
                    "transaction is not pending live verification"
                )
            if (
                not self._journal["resume"]
                or self._journal["issued"] is None
                or self._journal["issued"]["chain"][0] != fingerprint
            ):
                raise UnifiOperationError(
                    "live certificate does not identify the pending transaction"
                )
            if not self._service.running():
                raise UnifiOperationError("UniFi service is not running")
            self._validate_live_verified_files(
                rollback_optional=self._journal["phase"] == "live_verified"
            )
            if self._journal["phase"] != "live_verified":
                # External success is durable before any recovery object is removed.
                self._phase("live_verified")
            self._establish_live_verified_durability()
            self._finish_live_verified()
            return "renewal_finalized"

    def _establish_live_verified_durability(self) -> None:
        """Re-establish file/content and namespace durability before cleanup.

        A journal replacement can be readable after rename but before the
        replacing directory entry was durably synchronized. Readability alone
        therefore never authorizes rollback removal.
        """

        if self._journal["phase"] != "live_verified":
            raise UnifiOperationError("transaction is not durably live verified")
        journal_info = self._files.status(JOURNAL)
        self._files.sync_file(JOURNAL)
        self._files.same(JOURNAL, journal_info)
        self._files.sync_directory()
        self._files.same(JOURNAL, journal_info)

    def _validate_live_verified_files(self, *, rollback_optional: bool) -> None:
        canonical_info = self._files.status(CANONICAL)
        if (
            canonical_info.st_nlink != 1
            or _inode(canonical_info) != self._journal["stage_inode"]
            or _public_id(self._collect(CANONICAL)) != self._journal["issued"]
        ):
            raise UnifiOperationError("pending canonical certificate changed")
        if self._files.exists(ROLLBACK):
            rollback_info = self._files.status(ROLLBACK)
            if (
                rollback_info.st_nlink != 1
                or _inode(rollback_info) != self._journal["old_inode"]
                or _public_id(self._collect(ROLLBACK)) != self._journal["old"]
            ):
                raise UnifiOperationError("pending rollback changed")
        elif not rollback_optional:
            raise UnifiOperationError("pending rollback is missing")
        if self._files.exists(STAGE):
            raise UnifiOperationError("unexpected pending stage")
        if self._files.exists(JOURNAL_NEW):
            raise UnifiOperationError("unexpected pending journal replacement")

    def _finish_live_verified(self) -> None:
        if self._journal["phase"] != "live_verified":
            raise UnifiOperationError("transaction is not durably live verified")
        # Unlink is atomic. Sync before journal removal makes rollback disposal
        # durable; a crash before that point leaves live_verified authority to retry.
        self._files.remove(ROLLBACK)
        self._files.sync_directory()
        self._files.remove(JOURNAL)
        self._files.sync_directory()

    def recover(self, *, startup=False) -> str:
        """Recover without import/signing; startup mode leaves Java for s6 to start."""
        if type(startup) is not bool:
            raise UnifiOperationError("invalid recovery mode")
        with self._locked():
            if not self._files.exists(JOURNAL):
                self._no_transaction()
                # Completes a possibly interrupted post-unlink directory sync.
                self._files.sync_directory()
                return "no_active_transaction"
            self._journal = _validate_journal(self._files.read_journal())
            if self._journal["phase"] == "live_verified":
                self._establish_live_verified_durability()
                self._validate_live_verified_files(rollback_optional=True)
                self._finish_live_verified()
                return "renewal_finalized"
            self._expect_stopped = True
            self._service.stop()
            journal = self._journal
            # Unsafe paths/owners are operator conditions, not corrupt content.
            canonical_info = self._files.status(CANONICAL)
            try:
                canonical = _public_id(self._collect(CANONICAL))
            except Exception:
                canonical = None
            self._files.same(CANONICAL, canonical_info)
            rollback = self._files.exists(ROLLBACK)
            if rollback:
                rollback_info = self._files.status(ROLLBACK)
                if (
                    _inode(self._files.status(ROLLBACK)) != journal["old_inode"]
                    or _public_id(self._collect(ROLLBACK)) != journal["old"]
                ):
                    raise UnifiOperationError(
                        "unexpected rollback; operator recovery required"
                    )
            elif (
                journal["rollback_expected"]
                and _inode(canonical_info) != journal["old_inode"]
            ):
                raise UnifiOperationError("required rollback missing")
            if (
                canonical == journal["old"]
                and _inode(canonical_info) == journal["old_inode"]
            ):
                outcome = "recovered_old"
            elif (
                journal["commit_possible"]
                and rollback
                and canonical == journal["issued"]
                and _inode(canonical_info) == journal["stage_inode"]
            ):
                outcome = "service_resumed_pending_live_verification"
            elif (
                canonical is None
                and rollback
                and journal["commit_possible"]
                and _inode(canonical_info)
                in [journal["old_inode"], journal["stage_inode"]]
            ):
                self._service.stopped()
                self._files.same(ROLLBACK, rollback_info)
                self._files.same(CANONICAL, canonical_info)
                self._files.replace(ROLLBACK, CANONICAL)
                self._files.sync_directory()
                if (
                    _public_id(self._collect(CANONICAL)) != journal["old"]
                    or _inode(self._files.status(CANONICAL)) != journal["old_inode"]
                ):
                    raise UnifiOperationError("rollback restoration failed")
                outcome = "recovered_old"
            else:
                raise UnifiOperationError(
                    "unexpected canonical; operator recovery required"
                )
            # Stage may be an incomplete/corrupt write. Validate its path and
            # recorded inode before unlinking, never interpret its bytes in Python.
            if self._files.exists(STAGE):
                staged = self._files.status(STAGE)
                if (
                    journal["stage_inode"] is not None
                    and _inode(staged) != journal["stage_inode"]
                ):
                    raise UnifiOperationError("unexpected recovery stage")
            self._service.stopped()
            self._resume_service(startup=startup)
            self._phase(outcome)
            if outcome == "recovered_old":
                for name in (STAGE, ROLLBACK, JOURNAL_NEW):
                    self._files.remove(name)
                self._files.sync_directory()
                self._files.remove(JOURNAL)
                self._files.sync_directory()
            return outcome
