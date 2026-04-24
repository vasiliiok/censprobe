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
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

WORKSPACE = Path(os.getenv("WORKSPACE", "/workspace"))

GIT_ENV = {
    **os.environ,
    "GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes",
    "GIT_AUTHOR_NAME": "censprobe-bot",
    "GIT_AUTHOR_EMAIL": "starvasyaa@gmail.com",
    "GIT_COMMITTER_NAME": "censprobe-bot",
    "GIT_COMMITTER_EMAIL": "starvasyaa@gmail.com",
}


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a git command synchronously in WORKSPACE."""
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


def git_pull() -> str:
    """Pull latest changes. Returns stdout."""
    logger.info("git pull ...")
    r = _run(["git", "pull", "--rebase"])
    logger.info("git pull done: %s", r.stdout.strip())
    return r.stdout


def git_add_commit_push(message: str, paths: list[str] | None = None) -> None:
    """
    Stage, commit, and push changes.

    Flow:
        1. Stage the requested paths (or everything if paths=None).
        2. Check if there's anything to commit; if not, bail out.
        3. Commit locally — working tree becomes clean re: staged changes.
        4. Push; on non-fast-forward, rebase our commit on top of remote and retry.

    Notes:
        * We do NOT pre-pull. Pulling only when push is rejected saves a network
          round-trip in the happy path (single pusher) and still handles the rare
          concurrent-push case via _push_with_retry.
        * Unrelated unstaged changes (e.g. other generated files we're not
          committing this run) are handled by `git pull --rebase --autostash`
          inside the retry loop.
    """
    # 1. Stage
    if paths:
        for p in paths:
            _run(["git", "add", p])
    else:
        _run(["git", "add", "-A"])

    # 2. Anything to commit?
    status = _run(["git", "status", "--porcelain", "--untracked-files=no"], check=False)
    if not status.stdout.strip():
        logger.info("Nothing to commit, skipping push.")
        return

    # 3. Commit locally.
    logger.info("git commit: %s", message)
    _run(["git", "commit", "-m", message])

    # 4. Push (with rebase on rejection).
    _push_with_retry()


def _push_with_retry(max_attempts: int = 4, backoff_sec: float = 2.0) -> None:
    """Push with exponential backoff; on rejection, rebase our commit on remote."""
    import time

    delay = backoff_sec
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info("git push (attempt %d/%d) ...", attempt, max_attempts)
            _run(["git", "push"])
            logger.info("git push succeeded.")
            return
        except RuntimeError as e:
            if attempt >= max_attempts:
                logger.error(
                    "Push failed after %d attempts. Commit is saved locally in %s; "
                    "run 'git push' manually when network is available.",
                    max_attempts, WORKSPACE,
                )
                return

            # Non-fast-forward or transient — put our commit on top of remote.
            try:
                _run(["git", "pull", "--rebase", "--autostash"])
            except RuntimeError as rebase_err:
                logger.warning("pull --rebase failed: %s", rebase_err)
                # Clean up any half-applied rebase so the next attempt isn't blocked.
                _run(["git", "rebase", "--abort"], check=False)

            logger.warning("Push rejected (attempt %d): %s. Retrying in %.1fs...", attempt, e, delay)
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
