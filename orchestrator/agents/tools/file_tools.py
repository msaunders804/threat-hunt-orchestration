#declare all file related tools
#v1: read_tasks, update_status, read_kb, write_notes
import json
import logging
import os
import re
import yaml
from datetime import date
from pathlib import Path

from dotenv import set_key

logger = logging.getLogger(__name__)

_DOTENV_PATH = Path(__file__).parents[3] / ".env"


def _get_shared_folder() -> Path:
    path = os.environ.get("SHARED_FOLDER", "").strip()
    if not path:
        raise RuntimeError(
            "SHARED_FOLDER is not configured. "
            "Call list_obsidian_vaults to see available vaults, "
            "then call set_shared_folder to configure one."
        )
    p = Path(path)
    if not p.exists():
        raise RuntimeError(
            f"SHARED_FOLDER path does not exist: {path}. "
            "The vault may have been rotated. Call list_obsidian_vaults to reconfigure."
        )
    return p


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split YAML frontmatter from markdown body. Returns (props, body)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    try:
        props = yaml.safe_load(text[3:end].strip()) or {}
    except Exception:
        props = {}
    return props, text[end + 4:].lstrip("\n")


def list_obsidian_vaults() -> str:
    """List all Obsidian vaults registered on this machine.

    Use this when SHARED_FOLDER is not configured or the configured path no longer
    exists. Returns a numbered list of vault names and paths so the user can pick
    the active shared vault.
    """
    obsidian_config = Path(os.environ.get("APPDATA", "")) / "obsidian" / "obsidian.json"
    if not obsidian_config.exists():
        return "Obsidian config not found. Is Obsidian installed and opened at least once?"

    try:
        data = json.loads(obsidian_config.read_text(encoding="utf-8"))
    except Exception as exc:
        return f"Failed to read Obsidian config: {exc}"

    vaults = data.get("vaults", {})
    if not vaults:
        return "No vaults found in Obsidian config."

    lines = ["Available Obsidian vaults:"]
    for i, (_vid, info) in enumerate(vaults.items(), 1):
        vault_path = info.get("path", "unknown")
        vault_name = Path(vault_path).name
        exists_marker = "(accessible)" if Path(vault_path).exists() else "(NOT FOUND)"
        lines.append(f"{i}. **{vault_name}** — `{vault_path}` {exists_marker}")

    lines.append("\nCall set_shared_folder with the full path to configure one.")
    return "\n".join(lines)


def set_shared_folder(path: str) -> str:
    """Set the shared Obsidian vault path used by all file tools.

    Call this after the user selects a vault from list_obsidian_vaults, or when
    they provide a new path directly. Persists across restarts.

    Args:
        path: Full filesystem path to the shared Obsidian vault folder.
    """
    p = Path(path)
    if not p.exists():
        return f"Path does not exist: {path}. Verify the path and try again."

    set_key(str(_DOTENV_PATH), "SHARED_FOLDER", str(p))
    os.environ["SHARED_FOLDER"] = str(p)
    logger.info("SHARED_FOLDER set to: %s", p)
    return f"Shared folder configured: `{p}`"


def read_task_list() -> str:
    """Read all open agent tasks from the TaskNotes folder in the shared vault.

    Scans TaskNotes/ for task notes where assignee is 'agent' and status is not 'done'.
    Returns filename, status, and title for each task — pass the filename to
    update_task_status to claim or complete a task.
    """
    shared = _get_shared_folder()
    tasknotes_dir = shared / "TaskNotes"
    if not tasknotes_dir.exists():
        return f"TaskNotes folder not found at {tasknotes_dir}."

    tasks = []
    for md_file in sorted(tasknotes_dir.rglob("*.md")):
        try:
            props, _ = _parse_frontmatter(md_file.read_text(encoding="utf-8"))
            if str(props.get("assignee", "")).strip().lower() != "donut":
                continue
            status = str(props.get("status", "open")).strip()
            if status == "done":
                continue
            title = props.get("title", md_file.stem)
            tasks.append(f"File: {md_file.name} | Status: {status} | Title: {title}")
        except Exception as exc:
            logger.warning("Could not read %s: %s", md_file, exc)

    if not tasks:
        return "No open agent tasks found in TaskNotes."

    return "Agent tasks:\n" + "\n".join(tasks)


def update_task_status(filename: str, new_status: str) -> str:
    """Update the status property of a TaskNotes task file.

    Args:
        filename: The task note filename as returned by read_task_list (e.g. 'my-task.md').
        new_status: 'in_progress' to set status to in-progress, 'complete' to set done.
    """
    shared = _get_shared_folder()
    tasknotes_dir = shared / "TaskNotes"

    status_map = {"in_progress": "in-progress", "complete": "done"}
    if new_status not in status_map:
        return f"Invalid status '{new_status}'. Use 'in_progress' or 'complete'."

    matches = list(tasknotes_dir.rglob(filename))
    if not matches:
        return f"Task file '{filename}' not found in TaskNotes folder."
    task_file = matches[0]

    new_value = status_map[new_status]
    content = task_file.read_text(encoding="utf-8")
    updated = re.sub(r"^(status:\s*).*$", f"\\g<1>{new_value}", content, flags=re.MULTILINE)

    if updated == content:
        return f"Could not find 'status:' property in {filename}. Is this a valid TaskNote?"

    task_file.write_text(updated, encoding="utf-8")
    logger.info("Task %s marked %s", filename, new_status)
    return f"Task '{filename}' marked {new_status}."


def read_knowledge_base() -> str:
    """Read all notes in the shared folder as context before starting any task.

    Returns every .md file under the shared folder (excluding Tasks/Tasks.md),
    concatenated with filename headers. Always call this before beginning work
    on a task or answering a hunt question.
    """
    shared = _get_shared_folder()
    tasknotes_dir = (shared / "TaskNotes").resolve()

    sections = []
    for md_file in sorted(shared.rglob("*.md")):
        try:
            md_file.resolve().relative_to(tasknotes_dir)
            continue  # inside TaskNotes — skip
        except ValueError:
            pass
        try:
            content = md_file.read_text(encoding="utf-8").strip()
            if content:
                rel = md_file.relative_to(shared)
                sections.append(f"### {rel}\n\n{content}")
        except Exception as exc:
            logger.warning("Could not read %s: %s", md_file, exc)

    if not sections:
        return "No notes found in the shared folder yet."

    return "# Knowledge Base\n\n" + "\n\n---\n\n".join(sections)

def write_hunt_note(task_title: str, content: str) -> str:
    """Write a hunt note to Donut Memory in the shared folder.

    Call this after completing a task to record findings for future sessions.
    The note will be returned by read_knowledge_base going forward.

    Args:
        task_title: Short title used in the filename.
        content: Full markdown content of the hunt note.
    """
    shared = _get_shared_folder()
    memory_dir = shared / "Donut Memory"
    memory_dir.mkdir(exist_ok=True)

    safe_title = re.sub(r'[\\/:*?"<>|]', "-", task_title).strip()
    filename = f"{date.today().isoformat()} - {safe_title}.md"
    note_path = memory_dir / filename

    note_path.write_text(content, encoding="utf-8")
    logger.info("Hunt note written: %s", note_path)
    return f"Hunt note saved: `Donut Memory/{filename}`"

