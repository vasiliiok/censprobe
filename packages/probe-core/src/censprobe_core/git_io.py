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
        2. Stash staged changes + unstaged changes.
        3. git pull --rebase to align with remote (avoids non-fast-forward).
        4. Pop stash back.
        5. Re-stage, check if anything changed, commit, push.

    Args:
        message: Commit message.
        paths: List of paths to stage. If None, stages everything (git add -A).
    """
    # 1. Stash any local changes (tracked + untracked) so pull --rebase is clean.
    _run(["git", "add", "-N", "."], check=False)   # include untracked in stash
    stash = _run(["git", "stash", "push", "-u", "-m", "censprobe-autosync"], check=False)
    stashed = "No local changes to save" not in (stash.stdout + stash.stderr)

    # 2. Sync with remote before committing to avoid non-fast-forward.
    try:
        _run(["git", "pull", "--rebase", "--autostash"])
    except RuntimeError as e:
        logger.warning("Pre-push pull failed: %s (continuing)", e)

    # 3. Restore stashed work.
    if stashed:
        try:
            _run(["git", "stash", "pop"])
        except RuntimeError as e:
            logger.error("Stash pop failed — resolve conflicts manually: %s", e)
            raise

    # 4. Stage the paths for this commit.
    if paths:
        for p in paths:
            _run(["git", "add", p])
    else:
        _run(["git", "add", "-A"])

    # 5. Check if there's anything to commit.
    status = _run(["git", "status", "--porcelain"], check=False)
    if not status.stdout.strip():
        logger.info("Nothing to commit, skipping push.")
        return

    logger.info("git commit: %s", message)
    _run(["git", "commit", "-m", message])

    _push_with_retry()


def _push_with_retry(max_attempts: int = 4, backoff_sec: float = 2.0) -> None:
    """Push with exponential backoff retry and automatic rebase on rejection."""
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
                logger.error("Push failed after %d attempts. Report saved in local commit.", max_attempts)
                logger.error("Run 'git push' manually from %s when network is available.", WORKSPACE)
                return

            # Rebase on top of latest remote before next attempt
            try:
                _run(["git", "pull", "--rebase"])
            except RuntimeError as rebase_err:
                logger.warning("Rebase also failed: %s", rebase_err)

            logger.warning("Push failed (attempt %d): %s. Retrying in %.1fs...", attempt, e, delay)
            time.sleep(delay)
            delay *= 2  # exponential backoff


async def git_pull_async() -> str:
    """Async wrapper for git pull."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, git_pull)


async def git_add_commit_push_async(message: str, paths: list[str] | None = None) -> None:
    """Async wrapper for git add/commit/push."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, git_add_commit_push, message, paths)
