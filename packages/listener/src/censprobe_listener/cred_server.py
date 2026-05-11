"""
cred_server.py — Ephemeral HTTPS endpoint that hands credentials to the client.

Replaces the old "commit protocols.yaml to git, client git-pulls it" flow.
Now the listener generates fresh credentials on every start, exposes them
on a dedicated TLS port with a one-shot bearer token, prints a single
``docker compose ... up`` command for the operator to copy onto the client
machine, and tears the endpoint down on Ctrl+C.

Security model:
  * Self-signed cert generated at start; the SHA-256 fingerprint is
    embedded in the printed client command, and the client validates it
    via cert pinning. A MitM presenting a different cert is rejected
    even though the chain isn't trust-anchored.
  * Bearer token = 32 bytes of secrets.token_urlsafe — 256 bits of
    entropy. Compared with hmac.compare_digest to avoid timing leaks.
  * Server is bound to 0.0.0.0 (the listener already runs ``network_mode:
    host``, so 0.0.0.0 is the host's external interface).

Lifecycle:
  start() spawns a daemon thread serving HTTPS; stop() shuts it down
  (synchronous; safe to call from asyncio via to_thread).
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import http.server
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import tempfile
import threading
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from censprobe_core.utils import write_secret
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from censprobe_listener._responder_dispatch import Responder

logger = logging.getLogger(__name__)


_CERT_VALIDITY_HOURS = 24  # cert lifetime; listener sessions are minutes
_TOKEN_BYTES = 32  # 256 bits of entropy
# Single-use token. The previous _MAX_SERVES=5 retry budget was a
# foot-gun: any party that snooped the bearer token (e.g. via `ps auxf`
# / /proc/<pid>/cmdline on the client host) had four extra fetches to
# steal the live VPN credentials before the legitimate retry consumed
# the last serve. With 1, the first authenticated fetch closes the
# window; a network-flaky client must restart the listener to retry.
_MAX_SERVES = 1


def generate_self_signed_cert() -> tuple[bytes, bytes, str]:
    """Generate an RSA-2048 self-signed cert.

    Returns (cert_pem, key_pem, sha256_fingerprint_hex).

    The cert carries a SubjectAlternativeName extension covering localhost
    plus the common cred-fetch addresses. The client pins by SHA-256
    fingerprint and disables hostname verification, but RFC 6125 strict
    clients (curl --cacert when an operator debugs by hand) refuse a
    CN-only cert outright — so we publish the SAN even though the pinned
    client doesn't consult it.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "censprobe-listener"),
        ]
    )
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("censprobe-listener"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv6Address("::1")),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(hours=_CERT_VALIDITY_HOURS))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, key_pem, fingerprint


class CredServer:
    """One-shot HTTPS endpoint serving the credentials YAML.

    Threading model: stdlib http.server runs in a daemon thread, so the
    asyncio event loop in main.py is never blocked by the request
    handlers (each request does a few sync I/O calls and exits).
    """

    def __init__(
        self,
        creds_yaml: str,
        port: int = 8443,
        # Listener intentionally exposes the credential endpoint to the
        # client over the public internet — the operator-supplied token
        # and pinned self-signed cert are what authenticate the request.
        # See module docstring for the threat model.
        bind: str = "0.0.0.0",  # noqa: S104  # nosec B104
    ) -> None:
        self.creds_bytes = creds_yaml.encode("utf-8")
        self.port = port
        self.bind = bind
        self.token = secrets.token_urlsafe(_TOKEN_BYTES)

        self._cert_pem, self._key_pem, self.cert_sha256 = generate_self_signed_cert()
        # Materialise PEMs to disk for SSLContext.load_cert_chain — Python's
        # ssl module can't load PEM bytes directly. They sit in a 0o700
        # tempdir so they're readable only by this process; both files get
        # cleaned up on stop(). ``write_secret`` opens with O_CREAT mode
        # 0o600 so the key is never world-readable, even briefly between
        # write_bytes() and a follow-up chmod.
        self._tmpdir = tempfile.mkdtemp(prefix="censprobe_cred_")
        self._cert_path = Path(self._tmpdir) / "cert.pem"
        self._key_path = Path(self._tmpdir) / "key.pem"
        write_secret(self._cert_path, self._cert_pem)
        write_secret(self._key_path, self._key_pem)

        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._serves_remaining = _MAX_SERVES
        self._lock = threading.Lock()
        # First IP to successfully fetch credentials. Captured under the
        # same lock that decrements _serves_remaining, so a request that
        # fails auth or runs after exhaustion never sets it. The asyncio
        # main loop reads `client_ip` after the listener stops, so a
        # plain str field plus the existing _lock is sufficient — no
        # event/condition variable is needed.
        self._client_ip: str | None = None
        # Set by main.py after responders have started so /snapshot can
        # read live counter state. ``None`` while responders are still
        # spinning up — /snapshot returns 503 until then.
        self._responders: dict[str, Responder] | None = None
        # Finalised post-stop snapshots — populated by main.py AFTER
        # _stop_responders has captured each responder's final state.
        # Until then ``/snapshot`` (which is now post-stop only) replies
        # 503 — the client polls with retries.
        self._final_snapshots: dict[str, dict[str, Any]] | None = None
        # Set by the snapshot handler once the client has successfully
        # GET /snapshot at least once AFTER commit_final_snapshots — so
        # main.py can wait_for(snapshot_drained, timeout=N) before
        # tearing the cred-server down. Without this the listener
        # would close the HTTPS port mid-polling, the client would
        # see ConnectionRefused after the 503-then-200 transition.
        self._snapshot_drained = threading.Event()
        # Set by an authenticated POST to /stop. main.py's
        # _wait_for_shutdown_signal awaits this in addition to
        # SIGINT/SIGTERM, so the client can ask the listener to
        # tear down as soon as probes finish (instead of relying on
        # the operator hitting Ctrl+C on the server terminal).
        self._stop_requested = threading.Event()
        # Asyncio Event mirror — set from inside the http.server thread
        # via loop.call_soon_threadsafe in main.py. The threading
        # Event above is the source of truth for the HTTP handler;
        # the asyncio mirror is what _wait_for_shutdown_signal awaits.
        self._stop_asyncio_event: asyncio.Event | None = None
        self._stop_event_loop: asyncio.AbstractEventLoop | None = None

    def start(self) -> None:
        handler_cls = self._make_handler()
        # ThreadingHTTPServer so a slow client doesn't block a parallel
        # legitimate retry. Bound to 0.0.0.0 — listener uses host
        # networking, so the host's external interface is reachable.
        self._server = http.server.ThreadingHTTPServer(
            (self.bind, self.port),
            handler_cls,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Floor at TLS 1.2 — we don't need 1.0/1.1 for any real client and
        # disabling them removes a row of historical CVE surface (BEAST,
        # POODLE-on-TLS-1.0, weak block ciphers). The pinned censprobe-client
        # always negotiates 1.2+ on Python 3.10+.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(self._cert_path), keyfile=str(self._key_path))
        # Wrap the listening socket once; HTTPServer's accept() will return
        # SSL-wrapped client sockets via ssl.SSLContext.wrap_socket below.
        self._server.socket = ctx.wrap_socket(
            self._server.socket,
            server_side=True,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="cred-server",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Credentials endpoint listening on https://%s:%d/creds",
            self.bind,
            self.port,
        )

    def attach_responders(self, responders: dict[str, Responder]) -> None:
        """Plug the running responders dict into the cred-server.

        Called from main.py once ``_start_responders`` has populated
        the dict. After this call, the /snapshot endpoint starts
        returning per-protocol live counter values; before it, the
        endpoint replies 503 (Service Unavailable) so an over-eager
        client can't race responder startup.
        """
        with self._lock:
            self._responders = responders

    def detach_responders(self) -> None:
        """Mirror of :meth:`attach_responders` — called from main.py
        right before the responders are stopped, so /snapshot stops
        reading counters that are about to disappear.
        """
        with self._lock:
            self._responders = None

    def bind_stop_event(self, ev: asyncio.Event, loop: asyncio.AbstractEventLoop) -> None:
        """Wire the asyncio Event ``_wait_for_shutdown_signal`` is
        awaiting into the cred-server, so the HTTP /stop handler can
        flip it via ``loop.call_soon_threadsafe`` from the daemon
        thread. Called once from main.py right after the responders
        are attached.
        """
        with self._lock:
            self._stop_asyncio_event = ev
            self._stop_event_loop = loop
            already_set = self._stop_requested.is_set()
        # If a client already POSTed /stop before main.py bound the
        # event (could happen if the client races past attach_responders
        # — unlikely but possible on a slow VM), set it now so the
        # listener doesn't hang waiting for a second signal.
        if already_set:
            loop.call_soon_threadsafe(ev.set)

    def wait_snapshot_drained(self, timeout: float) -> bool:
        """Block (in a worker thread) until /snapshot has served the
        committed dict at least once, or ``timeout`` elapses. Returns
        ``True`` if drained, ``False`` on timeout. Used by main.py to
        keep the cred-server up just long enough for the client's
        polling pull to land — but no longer than ``timeout`` so an
        operator who Ctrl+C'd manually (no client to wait for) still
        gets a bounded shutdown.
        """
        return self._snapshot_drained.wait(timeout=timeout)

    def commit_final_snapshots(self, snapshots: dict[str, dict[str, Any]]) -> None:
        """Publish the post-``stop()`` per-protocol LiveSnapshot dicts.

        Called from main.py AFTER ``_stop_responders`` has captured
        each responder's final counter state. Until this call,
        ``/snapshot`` replies 503; once committed, clients can
        retrieve the authoritative final view and assemble the
        cross-verification table.
        """
        with self._lock:
            self._final_snapshots = snapshots

    @property
    def client_ip(self) -> str | None:
        """IP of the first client that successfully fetched credentials.

        None means no client ever passed bearer-token auth — typically
        because the cred-endpoint was unreachable from the client
        network (firewall, blocked port). Read after stop() to decide
        whether to enrich client metadata or mark the session as
        client_connected=False.
        """
        with self._lock:
            return self._client_ip

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception as e:
                logger.warning("Cred server shutdown error: %s", e)
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        # Best-effort wipe of cert/key material from disk. The OS will
        # clean tmpdir on reboot if these races with another process.
        for p in (self._cert_path, self._key_path):
            with contextlib.suppress(Exception):
                p.unlink(missing_ok=True)
        with contextlib.suppress(Exception):
            Path(self._tmpdir).rmdir()

    def _make_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        srv = self  # closure for handler

        class _Handler(http.server.BaseHTTPRequestHandler):
            # Silence the default "code 200, message OK" stderr noise —
            # the Rich console is doing the user-facing logging.
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _reject(self, code: int, reason: str) -> None:
                self.send_response(code)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(reason.encode("utf-8"))

            def do_GET(self) -> None:  # noqa: N802 — http.server method name
                if self.path == "/creds":
                    self._serve_creds()
                    return
                if self.path == "/snapshot":
                    self._serve_snapshot()
                    return
                self._reject(404, "not found")

            def _check_bearer(self) -> bool:
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    self._reject(401, "missing bearer token")
                    return False
                presented = auth[len("Bearer ") :]
                if not hmac.compare_digest(presented, srv.token):
                    self._reject(403, "invalid token")
                    return False
                return True

            def _serve_creds(self) -> None:
                if not self._check_bearer():
                    return
                with srv._lock:
                    if srv._serves_remaining <= 0:
                        self._reject(410, "credentials exhausted")
                        return
                    srv._serves_remaining -= 1
                    # Record the first authenticated client. Subsequent
                    # successful fetches (slow client retrying inside
                    # _MAX_SERVES) keep the original; we want the
                    # endpoint identity, not the latest replay.
                    if srv._client_ip is None:
                        # client_address is (ip, port); take the IP only.
                        srv._client_ip = self.client_address[0]

                self.send_response(200)
                self.send_header("Content-Type", "application/yaml; charset=utf-8")
                self.send_header("Content-Length", str(len(srv.creds_bytes)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(srv.creds_bytes)

            def _serve_snapshot(self) -> None:
                """Per-protocol counter snapshot for cross-verification.

                Authenticates with the same bearer token as ``/creds`` —
                anyone who fetched credentials already knows it, and
                snapshots are read-only state, so we don't need a
                separate auth scope.

                Semantics change (2026-05): the snapshot is no longer a
                live read of running responders. The client first POSTs
                ``/stop`` to ask the listener to tear down, then polls
                ``/snapshot`` (with retries) until ``commit_final_snapshots``
                has been called — at which point this endpoint returns
                the SAME per-protocol counters that ``stop()`` captured
                for the JSON report. That eliminates the race seen with
                amneziawg-go where a live read mid-session could see
                rx_bytes>0 while ``stop()`` minutes later saw rx=0 once
                the userspace daemon GC'd the unhandshaked peer.
                """
                if not self._check_bearer():
                    return
                with srv._lock:
                    final = srv._final_snapshots
                if final is None:
                    self._reject(
                        503,
                        "session not finalized — POST /stop first, then retry",
                    )
                    return

                payload = json.dumps(final, separators=(",", ":")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)
                # Tell main.py the client has its data — it can now safely
                # shut down the cred-server without truncating a polling
                # client. Idempotent: ``Event.set()`` is no-op after first.
                srv._snapshot_drained.set()

            def do_POST(self) -> None:  # noqa: N802
                if self.path == "/stop":
                    self._serve_stop()
                    return
                self._reject(405, "method not allowed")

            def _serve_stop(self) -> None:
                """Client-driven shutdown trigger.

                Authenticated POST that flips an asyncio Event main.py
                is awaiting alongside SIGINT/SIGTERM, so the listener
                can stop on a client request as soon as probes finish
                instead of relying on the operator hitting Ctrl+C on
                the server terminal. Multi-serve and idempotent — the
                Event is set once; further calls return 200 cheaply.

                We respond BEFORE flipping the event so the client
                doesn't hold the TCP connection open while the
                listener tears down (responder.stop() can take 30+s
                for openvpn/wg).
                """
                if not self._check_bearer():
                    return
                with srv._lock:
                    ev = srv._stop_asyncio_event
                    loop = srv._stop_event_loop

                self.send_response(202)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                body = b'{"status":"stop_requested"}'
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

                # Flip the asyncio Event from inside the http.server
                # thread via call_soon_threadsafe — the event is owned
                # by main.py's loop, which is on a different thread.
                # No-op if main.py hasn't bound the event yet (race
                # against responder startup); the threading mirror
                # keeps the "client asked to stop" intent recorded so
                # main.py can pick it up after binding.
                srv._stop_requested.set()
                if ev is not None and loop is not None:
                    loop.call_soon_threadsafe(ev.set)

        return _Handler


# Public IP echo services queried only when the kernel's local
# default-route source is a private/CGNAT/loopback address. Listed in
# fallback order; first one to return a parseable IPv4 wins.
_PUBLIC_IP_ECHOES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
)
_PUBLIC_IP_TIMEOUT_SEC = 5.0


def detect_external_ip() -> str | None:
    """Best-effort detection of the IPv4 a remote client should connect to.

    Two-step strategy:

      1. Kernel routing trick — open a UDP socket "connected" to a public
         anycast (SOCK_DGRAM connect never actually sends a packet) and
         ask the kernel which source address it would use. Instant, works
         on any host with a default route. On a cloud VPS with a directly
         attached public IP this is the answer.

      2. If step 1 returned a private/CGNAT/loopback address, the
         listener is behind NAT — the local source IP is useless to a
         remote client. Query a public-IP echo service to learn the
         externally-routable address. Bounded by ~5 s per endpoint.

    Returns ``None`` only if the host has no outbound network at all —
    in that case the listener cannot accept clients anyway, and main.py
    falls back to a placeholder ``<your-server-ip>`` in the printed
    command.
    """
    local_ip = _udp_connect_local_ip()
    if local_ip is None:
        return None

    if not _is_unroutable(local_ip):
        return local_ip

    public_ip = _query_public_ip_echo()
    return public_ip or local_ip


def _udp_connect_local_ip() -> str | None:
    """Return the IPv4 source address the kernel would use for a public destination."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip: str = s.getsockname()[0]
            return ip
        finally:
            s.close()
    except OSError:
        return None


_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def _is_unroutable(ip: str) -> bool:
    """Treat an IPv4 as unusable for a remote client.

    Covers all the cases where a behind-NAT listener would otherwise hand
    the client an IP it cannot reach:
      * RFC 1918 (10/8, 172.16/12, 192.168/16),
      * loopback (127/8) and link-local (169.254/16) — `is_private`
        captures both,
      * CGNAT (100.64/10, RFC 6598) — explicitly NOT covered by
        `is_private` in CPython, so we add a direct subnet membership
        check. Mobile uplinks and several budget VPS providers hand out
        CGNAT addresses, and falling through to the echo lookup is
        exactly the path we want for those listeners.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        # ipaddress.AddressValueError is a ValueError subclass — Sonar S5713.
        return True
    return addr.is_private or addr in _CGNAT_NETWORK


def _query_public_ip_echo() -> str | None:
    """Ask a couple of public-IP echo services and return the first parseable IPv4."""
    for url in _PUBLIC_IP_ECHOES:
        try:
            # urls are a hardcoded module-level tuple of trusted https endpoints
            # (api.ipify.org, ifconfig.me) — no operator/network input is mixed
            # into the URL, so the "audit URL open" warning doesn't apply.
            with urllib.request.urlopen(url, timeout=_PUBLIC_IP_TIMEOUT_SEC) as r:  # noqa: S310  # nosec B310
                ip: str = r.read().decode("ascii", errors="replace").strip()
            ipaddress.IPv4Address(ip)  # validate; raises if junk
            return ip
        except (OSError, ValueError):
            # ipaddress.AddressValueError is already a ValueError subclass.
            continue
    return None
