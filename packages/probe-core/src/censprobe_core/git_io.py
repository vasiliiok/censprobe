"""
git_io.py — Git operations helper for censprobe containers.

All containers (solo, listener, control) use the same pattern:
  1. Work in /workspace (the cloned repo mounted as volume)
  2. Write their results to the workspace
  3. Call git_add_commit_push() to publish
  4. Exit

SSH key is mounted at /root/.ssh from the host — no PAT tokens, no .env secrets.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))

# Path for a process-global advisory lock around any git operation.
# /workspace is bind-mounted and shared between solo / listener / sync-api
# containers; concurrent `git pull` + `git commit` race on .git/index.lock
# and kill one of them. fcntl.flock over a dedicated lock file on the
# shared volume (so other containers see the same inode) serialises them
# cleanly without needing a new dependency.
_GIT_LOCK_PATH = Path(
    os.getenv("CENSPROBE_GIT_LOCK", str(WORKSPACE / ".git" / "censprobe.lock"))
)

# Use a writable known_hosts path that survives a read-only ~/.ssh bind
# mount. StrictHostKeyChecking=accept-new tries to append to the
# known_hosts file on first connection; if the mount is read-only, SSH
# aborts the connection ("cannot create file ... read-only"). Pointing
# UserKnownHostsFile at /tmp keeps the accept-new flow working without
# weakening StrictHostKeyChecking to "no".
_SSH_KNOWN_HOSTS = os.getenv("CENSPROBE_KNOWN_HOSTS", "/tmp/censprobe_known_hosts")

# Committer identity is configurable per-deployment so a second operator
# can run censprobe without commits being attributed to the original author.
_GIT_NAME = os.getenv("CENSPROBE_GIT_NAME", "censprobe-bot")
_GIT_EMAIL = os.getenv("CENSPROBE_GIT_EMAIL", "noreply@censprobe.local")

GIT_ENV = {
    **os.environ,
    "GIT_SSH_COMMAND": (
        "ssh -o StrictHostKeyChecking=accept-new "
        "-o BatchMode=yes "
        f"-o UserKnownHostsFile={_SSH_KNOWN_HOSTS}"
    ),
    "GIT_AUTHOR_NAME": _GIT_NAME,
    "GIT_AUTHOR_EMAIL": _GIT_EMAIL,
    "GIT_COMMITTER_NAME": _GIT_NAME,
    "GIT_COMMITTER_EMAIL": _GIT_EMAIL,
}


@contextlib.contextmanager
def _git_lock() -> Iterator[None]:
    """Acquire an exclusive advisory lock covering the whole git operation.

    Prevents concurrent `git pull` / `git commit` from different
    containers racing on .git/index.lock and killing each other.
    """
    _GIT_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Open in 'a' (append) so the file is created if missing but never
    # truncated — important if two processes race the first creation.
    fd = os.open(str(_GIT_LOCK_PATH), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _run_unlocked(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command synchronously in WORKSPACE WITHOUT acquiring the lock.

    Use this when the caller already holds `_git_lock()` and wants to issue a
    multi-step git flow atomically. For one-shot calls outside an existing
    lock context, use `_run` instead.
    """
    result = subprocess.run(
        cmd,
        cwd=WORKSPACE,
        capture_output=True,
        text=True,
        env=GIT_ENV,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Git command failed: {' '.join(cmd)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command under the cross-container lock.

    For multi-step flows (stage → status → commit → push) prefer holding the
    lock once across all calls via `_git_lock()` + `_run_unlocked`; otherwise
    a peer container can interleave its own staged changes between our
    individual commands and we'd commit (or skip!) the wrong tree.
    """
    with _git_lock():
        return _run_unlocked(cmd, check)


def git_pull() -> str:
    """Pull latest changes. Returns stdout."""
    logger.info("git pull ...")
    r = _run(["git", "pull", "--rebase"])
    logger.info("git pull done: %s", r.stdout.strip())
    return r.stdout


def git_add_commit_push(
    message: str,
    paths: list[str] | None = None,
    max_attempts: int = 4,
    backoff_sec: float = 2.0,
) -> None:
    """
    Stage, commit, and push changes.

    Atomicity: stage+status+commit run inside a single fcntl-flock window so
    a peer container running in parallel can't slip its own `git add -A` in
    between our `add` and `commit`. The push retry loop releases the lock
    during its backoff sleep so peers can make progress while we wait.

    Flow:
        1. Stage the requested paths (or everything if paths=None).
        2. Check if there's anything to commit; if not, bail out.
        3. Commit locally — working tree becomes clean re: staged changes.
        4. Push; on non-fast-forward, rebase our commit on top of remote and retry.

    Notes:
        * We do NOT pre-pull. Pulling only when push is rejected saves a network
          round-trip in the happy path (single pusher) and still handles the rare
          concurrent-push case via the rebase-on-reject loop below.
        * Unrelated unstaged changes (e.g. other generated files we're not
          committing this run) are handled by `git pull --rebase --autostash`
          inside the retry loop.
    """
    # ── Stage + commit (atomic under the lock) ───────────────────────────────
    with _git_lock():
        if paths:
            for p in paths:
                _run_unlocked(["git", "add", p])
        else:
            _run_unlocked(["git", "add", "-A"])

        status = _run_unlocked(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            check=False,
        )
        if not status.stdout.strip():
            logger.info("Nothing to commit, skipping push.")
            return

        logger.info("git commit: %s", message)
        _run_unlocked(["git", "commit", "-m", message])

    # ── Push with rebase-on-reject (lock released between attempts) ──────────
    delay = backoff_sec
    for attempt in range(1, max_attempts + 1):
        with _git_lock():
            try:
                logger.info("git push (attempt %d/%d) ...", attempt, max_attempts)
                _run_unlocked(["git", "push"])
                logger.info("git push succeeded.")
                return
            except RuntimeError as e:
                if attempt >= max_attempts:
                    logger.error(
                        "Push failed after %d attempts. Commit is saved locally in %s. "
                        "Run 'git push' manually when network is available.",
                        max_attempts, WORKSPACE,
                    )
                    raise RuntimeError(
                        f"git push failed after {max_attempts} attempts. "
                        f"The commit is saved locally in {WORKSPACE}. "
                        f"To publish results manually, run: cd {WORKSPACE} && git push"
                    ) from e

                # Non-fast-forward or transient — put our commit on top of remote.
                try:
                    _run_unlocked(["git", "pull", "--rebase", "--autostash"])
                except RuntimeError as rebase_err:
                    logger.warning("pull --rebase failed: %s", rebase_err)
                    # Clean up any half-applied rebase so the next attempt isn't blocked.
                    _run_unlocked(["git", "rebase", "--abort"], check=False)

                logger.warning(
                    "Push rejected (attempt %d): %s. Retrying in %.1fs...",
                    attempt, e, delay,
                )

        # Sleep outside the lock so peers can make progress during backoff.
        time.sleep(delay)
        delay *= 2


async def git_pull_async() -> str:
    """Async wrapper for git pull."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, git_pull)


async def git_add_commit_push_async(message: str, paths: list[str] | None = None) -> None:
    """Async wrapper for git add/commit/push."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, git_add_commit_push, message, paths)
