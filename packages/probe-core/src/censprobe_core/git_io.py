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

    Args:
        message: Commit message.
        paths: List of paths to stage. If None, stages everything (git add -A).
    """
    # Stage
    if paths:
        for p in paths:
            _run(["git", "add", p])
    else:
        _run(["git", "add", "-A"])

    # Check if there's anything to commit
    status = _run(["git", "status", "--porcelain"], check=False)
    if not status.stdout.strip():
        logger.info("Nothing to commit, skipping push.")
        return

    # Commit
    logger.info("git commit: %s", message)
    _run(["git", "commit", "-m", message])

    # Push with retry
    _push_with_retry()


def _push_with_retry(max_attempts: int = 3, backoff_sec: float = 10.0) -> None:
    """Push with linear backoff retry."""
    import time

    for attempt in range(1, max_attempts + 1):
        try:
            logger.info("git push (attempt %d/%d) ...", attempt, max_attempts)
            _run(["git", "push"])
            logger.info("git push succeeded.")
            return
        except RuntimeError as e:
            if attempt < max_attempts:
                # Try rebase first in case of diverged history
                try:
                    _run(["git", "pull", "--rebase"])
                except RuntimeError:
                    pass
                logger.warning("Push failed (attempt %d): %s. Retrying in %ss...", attempt, e, backoff_sec)
                time.sleep(backoff_sec)
            else:
                logger.error("Push failed after %d attempts. Report saved locally.", max_attempts)
                logger.error("Run 'git push' manually from %s when network is available.", WORKSPACE)
                # Don't raise — the report is safe in the local commit


async def git_pull_async() -> str:
    """Async wrapper for git pull."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, git_pull)


async def git_add_commit_push_async(message: str, paths: list[str] | None = None) -> None:
    """Async wrapper for git add/commit/push."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, git_add_commit_push, message, paths)
