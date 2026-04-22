#!/usr/bin/env python3
"""
Memory Tool Module - Persistent Curated Memory

Provides bounded, file-backed memory that persists across sessions. Two stores:
  - MEMORY.md: agent's personal notes and observations (environment facts, project
    conventions, tool quirks, things learned)
  - USER.md: what the agent knows about the user (preferences, communication style,
    expectations, workflow habits)

Both are injected into the system prompt as a frozen snapshot at session start.
Mid-session writes update files on disk immediately (durable) but do NOT change
the system prompt -- this preserves the prefix cache for the entire session.
The snapshot refreshes on the next session start.

Entry delimiter: § (section sign). Entries can be multiline.
Character limits (not tokens) because char counts are model-independent.

Design:
- Single `memory` tool with action parameter: add, replace, remove, read
- replace/remove use short unique substring matching (not full text or IDs)
- Behavioral guidance lives in the tool schema description
- Frozen snapshot pattern: system prompt is stable, tool responses show live state
"""

import json
import logging
import os
import re
import shutil
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from hermes_constants import get_hermes_home
from typing import Dict, Any, List, Optional

# ---------------------------------------------------------------------------
# Phase 3 — Backup & Approval Guard
# ---------------------------------------------------------------------------
# Destructive memory operations (remove / replace) follow this flow:
#   1. Silent backup  — copies to ~/.hermes/memories/.removed/{timestamp}/
#   2. Preview        — shows what will change, marks op as PENDING
#   3. User approval  — user confirms (new call with action='delete_pending')
#   4. Execute        — actually mutates memory files / holographic DB
#
# Pending operations are stored in-memory on the MemoryStore instance so a
# subsequent 'delete_pending' call can find and execute them.
# ---------------------------------------------------------------------------

def get_removed_dir() -> Path:
    """Profile-scoped backup root: ~/.hermes/memories/.removed/"""
    removed = get_hermes_home() / "memories" / ".removed"
    removed.mkdir(parents=True, exist_ok=True)
    return removed


def _backup_memory_to_removed(target: str, entries_removed: List[str],
                               reason: str = "remove") -> Path:
    """Silent auto-backup: copy current state to .removed/{timestamp}/.

    The backup dir contains:
      - memory.md  (full current content at time of backup)
      - meta.json  (timestamp, reason, entries_removed)

    Returns the backup Path so callers can mention it in the preview.
    """
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = get_removed_dir() / ts
    backup_dir.mkdir(parents=True, exist_ok=True)

    mem_dir = get_memory_dir()
    source = mem_dir / (target.upper().replace("USER", "USER") + ".md")
    if source.exists():
        shutil.copy2(source, backup_dir / source.name)

    meta = {
        "timestamp": ts,
        "reason": reason,
        "target": target,
        "entries_removed": entries_removed,
    }
    (backup_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return backup_dir

# fcntl is Unix-only; on Windows use msvcrt for file locking
msvcrt = None
try:
    import fcntl
except ImportError:
    fcntl = None
    try:
        import msvcrt
    except ImportError:
        pass

logger = logging.getLogger(__name__)

# Where memory files live — resolved dynamically so profile overrides
# (HERMES_HOME env var changes) are always respected.  The old module-level
# constant was cached at import time and could go stale if a profile switch
# happened after the first import.
def get_memory_dir() -> Path:
    """Return the profile-scoped memories directory."""
    return get_hermes_home() / "memories"

ENTRY_DELIMITER = "\n§\n"


# ---------------------------------------------------------------------------
# Memory content scanning — lightweight check for injection/exfiltration
# in content that gets injected into the system prompt.
# ---------------------------------------------------------------------------

_MEMORY_THREAT_PATTERNS = [
    # Prompt injection
    (r'ignore\s+(previous|all|above|prior)\s+instructions', "prompt_injection"),
    (r'you\s+are\s+now\s+', "role_hijack"),
    (r'do\s+not\s+tell\s+the\s+user', "deception_hide"),
    (r'system\s+prompt\s+override', "sys_prompt_override"),
    (r'disregard\s+(your|all|any)\s+(instructions|rules|guidelines)', "disregard_rules"),
    (r'act\s+as\s+(if|though)\s+you\s+(have\s+no|don\'t\s+have)\s+(restrictions|limits|rules)', "bypass_restrictions"),
    # Exfiltration via curl/wget with secrets
    (r'curl\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)', "exfil_curl"),
    (r'wget\s+[^\n]*\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)', "exfil_wget"),
    (r'cat\s+[^\n]*(\.env|credentials|\.netrc|\.pgpass|\.npmrc|\.pypirc)', "read_secrets"),
    # Persistence via shell rc
    (r'authorized_keys', "ssh_backdoor"),
    (r'\$HOME/\.ssh|\~/\.ssh', "ssh_access"),
    (r'\$HOME/\.hermes/\.env|\~/\.hermes/\.env', "hermes_env"),
]

# Subset of invisible chars for injection detection
_INVISIBLE_CHARS = {
    '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff',
    '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
}

# Quality gate — patterns that suggest content belongs in a different tool.
# Returns a redirect dict if the content looks like a SKIP category, else None.
_MEMORY_SKIP_PATTERNS = [
    # Task progress / session outcomes / completed work logs
    (
        r'(完成|进展|进度|花了|用了多久|哪个session|结果如何|outcome|progress|'
        r'花了多少时间|这次对话|上次对话|本周任务)',
        "task_progress",
        "session_search — 查询历史会话记录来回顾任务进度和完成情况",
    ),
    # Code snippets, function/class definitions
    (
        r'^(def |class |import |from\s+\w+\s+import |async def |```(|python|js|ts|yaml|json)\s*$)',
        "code_snippet",
        "直接读取代码文件或使用 skill_manage 保存工作流，不要存代码片段到记忆",
    ),
    # Git / version control history
    (
        r'(git\s+(log|diff|blame|show|stash|branch|commit|merge|rebase|'
        r'HEAD~\d|origin/|PR\s+#)|commit\s+[0-9a-f]{7,})',
        "git_history",
        "terminal + git 命令查看版本历史，或用 session_search 查相关讨论",
    ),
    # File/directory listings or contents
    (
        r'(^\s*(?:/|[a-z]:\\).*?\.(py|js|ts|md|yaml|json|toml|go|rs|c|cpp)\s*$|'
        r'文件内容|file content|文件路径|path:)',
        "file_content",
        "直接读取文件或查文档，不要存文件内容到记忆",
    ),
    # Temporary TODO / reminders
    (
        r'(待办|提醒我|稍后|下次|TODO|FIXME|以后再|remind me to)',
        "todo_reminder",
        "todo 工具更适合记录待办事项",
    ),
    # Config values / secrets
    (
        r'(api_key|api[_-]?key|secret|password|token|credential)\s*[=:]\s*[\'"][^\'\"]+[\'"]',
        "secrets",
        "敏感信息不要存记忆，配置在 .env 或 config.yaml 中",
    ),
]


def _scan_memory_content(content: str) -> Optional[str]:
    """Scan memory content for injection/exfil patterns. Returns error string if blocked."""
    # Check invisible unicode
    for char in _INVISIBLE_CHARS:
        if char in content:
            return f"Blocked: content contains invisible unicode character U+{ord(char):04X} (possible injection)."

    # Check threat patterns
    for pattern, pid in _MEMORY_THREAT_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return f"Blocked: content matches threat pattern '{pid}'. Memory entries are injected into the system prompt and must not contain injection or exfiltration payloads."

    return None


def _check_memory_quality(content: str) -> Optional[Dict[str, str]]:
    """Gate for content quality — detect items that belong in a different tool.

    Returns a redirect dict with keys: category, suggestion, rule
    Returns None if content is appropriate for memory.
    """
    for pattern, category, suggestion in _MEMORY_SKIP_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
            # Only flag if the match looks like the PRIMARY content, not incidental mention.
            # Heuristic: if the first non-empty line matches, it's the primary content.
            first_meaningful = content.strip().split('\n')[0].strip()
            if re.search(pattern, first_meaningful, re.IGNORECASE | re.MULTILINE):
                return {
                    "category": category,
                    "suggestion": suggestion,
                    "rule": (
                        f"[SKIP:{category}] 这类内容不适合存记忆。"
                        f"建议：{suggestion}。"
                        f"如果确定要存，请调整格式后再试。"
                    ),
                }
    return None


class MemoryStore:
    """
    Bounded curated memory with file persistence. One instance per AIAgent.

    Maintains two parallel states:
      - _system_prompt_snapshot: frozen at load time, used for system prompt injection.
        Never mutated mid-session. Keeps prefix cache stable.
      - memory_entries / user_entries: live state, mutated by tool calls, persisted to disk.
        Tool responses always reflect this live state.
    """

    def __init__(self, memory_char_limit: int = 2200, user_char_limit: int = 1375):
        self.memory_entries: List[str] = []
        self.user_entries: List[str] = []
        self.memory_char_limit = memory_char_limit
        self.user_char_limit = user_char_limit
        # Frozen snapshot for system prompt -- set once at load_from_disk()
        self._system_prompt_snapshot: Dict[str, str] = {"memory": "", "user": ""}
        # Phase 3 — pending destructive operation awaiting user approval.
        # Shape: {"action": "remove"|"replace", "target": str,
        #         "old_text": str, "new_content": str|None,
        #         "match_idx": int, "entries_removed": List[str],
        #         "backup_path": str, "pending_since": float}
        self._pending_op: Optional[Dict[str, Any]] = None

    def load_from_disk(self):
        """Load entries from MEMORY.md and USER.md, capture system prompt snapshot."""
        mem_dir = get_memory_dir()
        mem_dir.mkdir(parents=True, exist_ok=True)

        self.memory_entries = self._read_file(mem_dir / "MEMORY.md")
        self.user_entries = self._read_file(mem_dir / "USER.md")

        # Deduplicate entries (preserves order, keeps first occurrence)
        self.memory_entries = list(dict.fromkeys(self.memory_entries))
        self.user_entries = list(dict.fromkeys(self.user_entries))

        # Capture frozen snapshot for system prompt injection
        self._system_prompt_snapshot = {
            "memory": self._render_block("memory", self.memory_entries),
            "user": self._render_block("user", self.user_entries),
        }

    @staticmethod
    @contextmanager
    def _file_lock(path: Path):
        """Acquire an exclusive file lock for read-modify-write safety.

        Uses a separate .lock file so the memory file itself can still be
        atomically replaced via os.replace().
        """
        lock_path = path.with_suffix(path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        if fcntl is None and msvcrt is None:
            yield
            return

        if msvcrt and (not lock_path.exists() or lock_path.stat().st_size == 0):
            lock_path.write_text(" ", encoding="utf-8")

        fd = open(lock_path, "r+" if msvcrt else "a+")
        try:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt:
                try:
                    fd.seek(0)
                    msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
                except (OSError, IOError):
                    pass
            fd.close()

    @staticmethod
    def _path_for(target: str) -> Path:
        mem_dir = get_memory_dir()
        if target == "user":
            return mem_dir / "USER.md"
        return mem_dir / "MEMORY.md"

    def _reload_target(self, target: str):
        """Re-read entries from disk into in-memory state.

        Called under file lock to get the latest state before mutating.
        """
        fresh = self._read_file(self._path_for(target))
        fresh = list(dict.fromkeys(fresh))  # deduplicate
        self._set_entries(target, fresh)

    def save_to_disk(self, target: str):
        """Persist entries to the appropriate file. Called after every mutation."""
        get_memory_dir().mkdir(parents=True, exist_ok=True)
        self._write_file(self._path_for(target), self._entries_for(target))

    def _entries_for(self, target: str) -> List[str]:
        if target == "user":
            return self.user_entries
        return self.memory_entries

    def _set_entries(self, target: str, entries: List[str]):
        if target == "user":
            self.user_entries = entries
        else:
            self.memory_entries = entries

    def _char_count(self, target: str) -> int:
        entries = self._entries_for(target)
        if not entries:
            return 0
        return len(ENTRY_DELIMITER.join(entries))

    def _char_limit(self, target: str) -> int:
        if target == "user":
            return self.user_char_limit
        return self.memory_char_limit

    def add(self, target: str, content: str) -> Dict[str, Any]:
        """Append a new entry. Returns error if it would exceed the char limit."""
        content = content.strip()
        if not content:
            return {"success": False, "error": "Content cannot be empty."}

        # Scan for injection/exfiltration before accepting
        scan_error = _scan_memory_content(content)
        if scan_error:
            return {"success": False, "error": scan_error}

        # Quality gate: detect content that belongs in a different tool
        quality_check = _check_memory_quality(content)
        if quality_check:
            return {
                "success": False,
                "error": quality_check["rule"],
                "redirect": quality_check["suggestion"],
            }

        with self._file_lock(self._path_for(target)):
            # Re-read from disk under lock to pick up writes from other sessions
            self._reload_target(target)

            entries = self._entries_for(target)
            limit = self._char_limit(target)

            # Reject exact duplicates
            if content in entries:
                return self._success_response(target, "Entry already exists (no duplicate added).")

            # Calculate what the new total would be
            new_entries = entries + [content]
            new_total = len(ENTRY_DELIMITER.join(new_entries))

            if new_total > limit:
                current = self._char_count(target)
                return {
                    "success": False,
                    "error": (
                        f"Memory at {current:,}/{limit:,} chars. "
                        f"Adding this entry ({len(content)} chars) would exceed the limit. "
                        f"Replace or remove existing entries first."
                    ),
                    "current_entries": entries,
                    "usage": f"{current:,}/{limit:,}",
                }

            entries.append(content)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry added.")

    def replace(self, target: str, old_text: str, new_content: str,
                _dry_run: bool = False) -> Dict[str, Any]:
        """Find entry containing old_text substring, replace with new_content.

        Phase 3: Always auto-backups before mutation. On first call stores
        pending op and returns PENDING. Call _dry_run=True to peek safely.
        """
        old_text = old_text.strip()
        new_content = new_content.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}
        if not new_content:
            return {"success": False, "error": "new_content cannot be empty. Use 'remove' to delete entries."}

        # Scan replacement content for injection/exfiltration
        scan_error = _scan_memory_content(new_content)
        if scan_error:
            return {"success": False, "error": scan_error}

        with self._file_lock(self._path_for(target)):
            self._reload_target(target)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return {"success": False, "error": f"No entry matched '{old_text}'."}

            if len(matches) > 1:
                unique_texts = set(e for _, e in matches)
                if len(unique_texts) > 1:
                    previews = [e[:80] + ("..." if len(e) > 80 else "") for _, e in matches]
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }

            idx = matches[0][0]
            old_entry = entries[idx]
            limit = self._char_limit(target)

            # Check that replacement doesn't blow the budget
            test_entries = entries.copy()
            test_entries[idx] = new_content
            new_total = len(ENTRY_DELIMITER.join(test_entries))

            if new_total > limit:
                return {
                    "success": False,
                    "error": (
                        f"Replacement would put memory at {new_total:,}/{limit:,} chars. "
                        f"Shorten the new content or remove other entries first."
                    ),
                }

            # Phase 3: Auto-backup BEFORE any mutation
            backup_path = _backup_memory_to_removed(
                target, [old_entry], reason="replace"
            )

            if _dry_run:
                return {"success": True, "entries": entries}

            # Phase 3: Store pending op, return PENDING
            self._pending_op = {
                "action": "replace",
                "target": target,
                "old_text": old_text,
                "new_content": new_content,
                "match_idx": idx,
                "entries_removed": [old_entry],
                "backup_path": str(backup_path),
                "pending_since": time.time(),
            }

            return {
                "success": True,
                "pending": True,
                "requires_approval": True,
                "action_type": "replace",
                "target": target,
                "old_preview": old_entry[:120] + ("..." if len(old_entry) > 120 else ""),
                "new_content": new_content,
                "backup_path": str(backup_path),
                "message": (
                    "⚠️  替换操作需要您确认。\n"
                    "已将完整记忆文件备份到：\n  "
                    + str(backup_path).replace(str(get_hermes_home()), "~/.hermes")
                    + "\n\n"
                    "如确认替换，请再次调用 memory(action='delete_pending', target='"
                    + target + "', old_text='" + old_text + "')。"
                ),
                "entries": entries,
            }

    def remove(self, target: str, old_text: str,
               _dry_run: bool = False) -> Dict[str, Any]:
        """Remove the entry containing old_text substring.

        Phase 3: Always auto-backups before showing preview. On first call
        (no _dry_run), stores pending op and returns PENDING status instead
        of executing. Call with _dry_run=True to peek without side effects.
        """
        old_text = old_text.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}

        with self._file_lock(self._path_for(target)):
            self._reload_target(target)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return {"success": False, "error": f"No entry matched '{old_text}'."}

            if len(matches) > 1:
                unique_texts = set(e for _, e in matches)
                if len(unique_texts) > 1:
                    previews = [e[:80] + ("..." if len(e) > 80 else "") for _, e in matches]
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }

            idx = matches[0][0]
            matched_entry = entries[idx]

            # Phase 3: Auto-backup the full file BEFORE any mutation
            backup_path = _backup_memory_to_removed(
                target, [matched_entry], reason="remove"
            )

            if _dry_run:
                return {"success": True, "entries": entries}

            # Phase 3: Store pending op, return PENDING instead of executing
            self._pending_op = {
                "action": "remove",
                "target": target,
                "old_text": old_text,
                "new_content": None,
                "match_idx": idx,
                "entries_removed": [matched_entry],
                "backup_path": str(backup_path),
                "pending_since": time.time(),
            }

            return {
                "success": True,
                "pending": True,
                "requires_approval": True,
                "action_type": "remove",
                "target": target,
                "entry_preview": matched_entry[:120] + ("..." if len(matched_entry) > 120 else ""),
                "backup_path": str(backup_path),
                "message": (
                    "⚠️  删除操作需要您确认。\n"
                    "已将完整记忆文件备份到：\n  "
                    + str(backup_path).replace(str(get_hermes_home()), "~/.hermes")
                    + "\n\n"
                    "如确认删除，请再次调用 memory(action='delete_pending', target='"
                    + target + "', old_text='" + old_text + "')。"
                ),
                "entries": entries,
            }

    def execute_pending_op(self) -> Dict[str, Any]:
        """Execute the stored pending destructive operation.

        Phase 3: User has confirmed. Perform the actual mutation now.
        Clears _pending_op on success or error.
        """
        if self._pending_op is None:
            return {"success": False, "error": "No pending operation to execute."}

        op = self._pending_op
        target = op["target"]
        backup_path = op["backup_path"]

        try:
            with self._file_lock(self._path_for(target)):
                self._reload_target(target)
                entries = self._entries_for(target)

                if op["action"] == "remove":
                    if op["match_idx"] < len(entries):
                        entries.pop(op["match_idx"])
                    self._set_entries(target, entries)
                    self.save_to_disk(target)

                elif op["action"] == "replace":
                    # Re-find in case entries changed since pending was set
                    matches = [
                        (i, e) for i, e in enumerate(entries)
                        if op["old_text"] in e
                    ]
                    if not matches:
                        self._pending_op = None
                        return {
                            "success": False,
                            "error": (
                                f"Entry containing '{op['old_text']}' no longer found "
                                "(may have been modified by another session). "
                                "Please retry the replace operation."
                            ),
                        }
                    idx = matches[0][0]
                    entries[idx] = op["new_content"]
                    self._set_entries(target, entries)
                    self.save_to_disk(target)

            self._pending_op = None
            short_backup = backup_path.replace(str(get_hermes_home()), "~/.hermes")
            return {
                "success": True,
                "action": op["action"],
                "target": target,
                "backup_path": backup_path,
                "message": (
                    f"✅ 已执行 {op['action']}，备份已保留。\n"
                    f"   备份位置：{short_backup}"
                ),
            }

        except Exception as e:
            self._pending_op = None
            return {"success": False, "error": f"Execute failed: {e}"}

    def archive(self, target: str, old_text: str) -> Dict[str, Any]:
        """Permanently archive an entry to .removed/ without removing from active memory.

        Use this when you want to keep a copy but also clean up the active file.
        Like a 'move to trash' rather than 'delete'.
        """
        old_text = old_text.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}

        with self._file_lock(self._path_for(target)):
            self._reload_target(target)
            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return {"success": False, "error": f"No entry matched '{old_text}'."}

            if len(matches) > 1:
                unique_texts = set(e for _, e in matches)
                if len(unique_texts) > 1:
                    previews = [e[:80] + ("..." if len(e) > 80 else "") for _, e in matches]
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }

            idx = matches[0][0]
            matched_entry = entries[idx]

            # Backup and remove
            backup_path = _backup_memory_to_removed(
                target, [matched_entry], reason="archive"
            )
            entries.pop(idx)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        short_backup = str(backup_path).replace(str(get_hermes_home()), "~/.hermes")
        return {
            "success": True,
            "action": "archive",
            "target": target,
            "backup_path": str(backup_path),
            "message": (
                f"✅ 已归档并从活跃记忆中移除。\n"
                f"   归档备份：{short_backup}"
            ),
            **self._success_response(target, "Entry archived."),
        }

    def list_pending_op(self) -> Dict[str, Any]:
        """Show the currently pending destructive operation, if any."""
        if self._pending_op is None:
            return {
                "success": True,
                "has_pending": False,
                "message": "No pending operation.",
            }
        op = self._pending_op
        age_seconds = time.time() - op["pending_since"]
        return {
            "success": True,
            "has_pending": True,
            "action": op["action"],
            "target": op["target"],
            "entry_preview": op["entries_removed"][0][:120]
                             + ("..." if len(op["entries_removed"][0]) > 120 else ""),
            "backup_path": op["backup_path"].replace(str(get_hermes_home()), "~/.hermes"),
            "pending_for_seconds": round(age_seconds),
            "message": (
                f"⏳ 待确认 {op['action']} 操作（已挂起 {int(age_seconds)}s）\n"
                f"   目标：{op['target']}\n"
                f"   内容预览：{op['entries_removed'][0][:80]}...\n"
                f"   备份：{op['backup_path'].replace(str(get_hermes_home()), '~/.hermes')}\n\n"
                f"如确认执行，请调用 memory(action='delete_pending', target='{op['target']}')。"
            ),
        }

    def format_for_system_prompt(self, target: str) -> Optional[str]:
        """
        Return the frozen snapshot for system prompt injection.

        This returns the state captured at load_from_disk() time, NOT the live
        state. Mid-session writes do not affect this. This keeps the system
        prompt stable across all turns, preserving the prefix cache.

        Returns None if the snapshot is empty (no entries at load time).
        """
        block = self._system_prompt_snapshot.get(target, "")
        return block if block else None

    # -- Internal helpers --

    def _success_response(self, target: str, message: str = None) -> Dict[str, Any]:
        entries = self._entries_for(target)
        current = self._char_count(target)
        limit = self._char_limit(target)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0

        resp = {
            "success": True,
            "target": target,
            "entries": entries,
            "usage": f"{pct}% — {current:,}/{limit:,} chars",
            "entry_count": len(entries),
        }
        if message:
            resp["message"] = message
        return resp

    def _render_block(self, target: str, entries: List[str]) -> str:
        """Render a system prompt block with header and usage indicator."""
        if not entries:
            return ""

        limit = self._char_limit(target)
        content = ENTRY_DELIMITER.join(entries)
        current = len(content)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0

        if target == "user":
            header = f"USER PROFILE (who the user is) [{pct}% — {current:,}/{limit:,} chars]"
        else:
            header = f"MEMORY (your personal notes) [{pct}% — {current:,}/{limit:,} chars]"

        separator = "═" * 46
        return f"{separator}\n{header}\n{separator}\n{content}"

    @staticmethod
    def _read_file(path: Path) -> List[str]:
        """Read a memory file and split into entries.

        No file locking needed: _write_file uses atomic rename, so readers
        always see either the previous complete file or the new complete file.
        """
        if not path.exists():
            return []
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, IOError):
            return []

        if not raw.strip():
            return []

        # Use ENTRY_DELIMITER for consistency with _write_file. Splitting by "§"
        # alone would incorrectly split entries that contain "§" in their content.
        entries = [e.strip() for e in raw.split(ENTRY_DELIMITER)]
        return [e for e in entries if e]

    @staticmethod
    def _write_file(path: Path, entries: List[str]):
        """Write entries to a memory file using atomic temp-file + rename.

        Previous implementation used open("w") + flock, but "w" truncates the
        file *before* the lock is acquired, creating a race window where
        concurrent readers see an empty file. Atomic rename avoids this:
        readers always see either the old complete file or the new one.
        """
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        try:
            # Write to temp file in same directory (same filesystem for atomic rename)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(path.parent), suffix=".tmp", prefix=".mem_"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, str(path))  # Atomic on same filesystem
            except BaseException:
                # Clean up temp file on any failure
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to write memory file {path}: {e}")


def memory_tool(
    action: str,
    target: str = "memory",
    content: str = None,
    old_text: str = None,
    store: Optional[MemoryStore] = None,
) -> str:
    """
    Single entry point for the memory tool. Dispatches to MemoryStore methods.

    Returns JSON string with results.
    """
    if store is None:
        return tool_error("Memory is not available. It may be disabled in config or this environment.", success=False)

    if target not in ("memory", "user"):
        return tool_error(f"Invalid target '{target}'. Use 'memory' or 'user'.", success=False)

    if action == "add":
        if not content:
            return tool_error("Content is required for 'add' action.", success=False)
        result = store.add(target, content)

    elif action == "replace":
        if not old_text:
            return tool_error("old_text is required for 'replace' action.", success=False)
        if not content:
            return tool_error("content is required for 'replace' action.", success=False)
        result = store.replace(target, old_text, content)

    elif action == "remove":
        if not old_text:
            return tool_error("old_text is required for 'remove' action.", success=False)
        result = store.remove(target, old_text)

    elif action == "delete_pending":
        result = store.execute_pending_op()

    elif action == "list_pending":
        result = store.list_pending_op()

    elif action == "archive":
        if not old_text:
            return tool_error("old_text is required for 'archive' action.", success=False)
        result = store.archive(target, old_text)

    elif action == "list_backups":
        from pathlib import Path
        removed_dir = get_removed_dir()
        if not removed_dir.exists():
            return json.dumps({"success": True, "backups": [], "count": 0})
        backups = sorted(removed_dir.iterdir(), reverse=True)
        infos = []
        for b in backups:
            meta_path = b / "meta.json"
            ts = b.name
            reason = ""
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    reason = meta.get("reason", "")
                except Exception:
                    pass
            infos.append({"path": str(b), "timestamp": ts, "reason": reason})
        return json.dumps({"success": True, "backups": infos, "count": len(infos)})

    else:
        return tool_error(f"Unknown action '{action}'. Use: add, replace, remove, delete_pending, archive, list_backups", success=False)

    return json.dumps(result, ensure_ascii=False)


def check_memory_requirements() -> bool:
    """Memory tool has no external requirements -- always available."""
    return True


# =============================================================================
# OpenAI Function-Calling Schema
# =============================================================================

MEMORY_SCHEMA = {
    "name": "memory",
    "description": (
        "Save durable information to persistent memory that survives across sessions.\n\n"
        "## Four types to save\n"
        "1. USER MEMORY (target='user') — user profile: role, background, preferences, "
        "communication style, pet peeves. Do NOT store negative evaluations or irrelevant privacy.\n"
        "2. FEEDBACK MEMORY — corrections and affirmations with rule + reason + scope.\n"
        "3. PROJECT MEMORY — state, owner, deadline (absolute dates, motivation not details).\n"
        "4. REFERENCE MEMORY — external resources, doc paths, authoritative references.\n\n"
        "## Five types to SKIP\n"
        "1. Anything retrievable by tools right now (file contents, git history)\n"
        "2. Task progress, completed work logs → use session_search\n"
        "3. Code/logic that lives in codebase → read the file\n"
        "4. Version control history → use terminal + git\n"
        "5. Temporary TODO state → use the todo tool\n\n"
        "## Redirect when asked to save the wrong thing\n"
        "If user asks to save something in a SKIP category, redirect them:\n"
        "  - 'what did we do last time?' / project history → session_search\n"
        "  - 'remind me to do X' / task list → todo tool\n"
        "  - workflow / approach / error fix → skill_manage\n"
        "  - current code / file contents → read the file directly\n\n"
        "## Write rules\n"
        "- Keep it compact — the most valuable memory prevents the user from repeating themselves\n"
        "- Before saving, ask: can I get this right now with a tool? If yes, don't save it\n"
        "- User preferences and corrections >> task details\n"
        "- Complex workflows (5+ tool calls) → save as skill instead\n\n"
        "## Phase 3 — Destructive operations require approval\n"
        "remove / replace automatically backup to ~/.hermes/memories/.removed/ "
        "and return PENDING status. You MUST present the preview to the user and "
        "ask for confirmation before calling delete_pending.\n"
        "archive: immediately move entry to backup (user already approved).\n"
        "list_pending: show current pending op status.\n\n"
        "ACTIONS: add, replace, remove, archive, delete_pending, list_pending, list_backups.\n\n"
        "SKIP: trivial/obvious info, things easily re-discovered, raw data dumps, temporary task state."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["add", "replace", "remove", "delete_pending", "list_pending", "archive", "list_backups"],
                "description": "The action to perform."
            },
            "target": {
                "type": "string",
                "enum": ["memory", "user"],
                "description": "Which memory store: 'memory' for personal notes, 'user' for user profile."
            },
            "content": {
                "type": "string",
                "description": "The entry content. Required for 'add' and 'replace'."
            },
            "old_text": {
                "type": "string",
                "description": "Short unique substring identifying the entry to replace or remove."
            },
        },
        "required": ["action", "target"],
    },
}


# --- Registry ---
from tools.registry import registry, tool_error

registry.register(
    name="memory",
    toolset="memory",
    schema=MEMORY_SCHEMA,
    handler=lambda args, **kw: memory_tool(
        action=args.get("action", ""),
        target=args.get("target", "memory"),
        content=args.get("content"),
        old_text=args.get("old_text"),
        store=kw.get("store")),
    check_fn=check_memory_requirements,
    emoji="🧠",
)




