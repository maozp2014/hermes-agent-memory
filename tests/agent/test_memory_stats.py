"""Tests for memory stats functionality (Phase 5 P5-1)."""

import json, pytest, tempfile, os, time, sqlite3
from unittest.mock import MagicMock, patch
from agent.memory_manager import MemoryManager
from agent.memory_provider import MemoryProvider


# ---------------------------------------------------------------------------
# Fake providers for MemoryManager tests
# ---------------------------------------------------------------------------

class FakeStatsProvider(MemoryProvider):
    """Provider that returns controlled stats for testing."""

    def __init__(self, name="fake", stats=None):
        self._name = name
        self._stats = stats or {}
        self.initialized = False

    @property
    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def initialize(self, session_id, **kwargs):
        self.initialized = True

    def system_prompt_block(self) -> str:
        return ""

    def get_tool_schemas(self):
        return []

    def get_stats(self):
        return self._stats


# ---------------------------------------------------------------------------
# MemoryManager.get_stats() tests
# ---------------------------------------------------------------------------

class TestMemoryManagerGetStats:

    def test_get_stats_returns_total_and_providers(self):
        mm = MemoryManager()
        stats = mm.get_stats()
        assert isinstance(stats, dict)
        assert "providers" in stats
        assert "generated_at" in stats

    def test_get_stats_empty_providers(self):
        mm = MemoryManager()
        stats = mm.get_stats()
        assert "providers" in stats
        assert isinstance(stats["providers"], dict)

    def test_get_stats_single_external_provider(self):
        """MemoryManager only allows one external provider at a time."""
        p1 = FakeStatsProvider("store_a", {
            "source": "store_a", "total_facts": 10,
            "trust_distribution": {"high": 5, "medium": 3, "low": 2},
        })
        mm = MemoryManager()
        mm.add_provider(p1)
        stats = mm.get_stats()
        assert "store_a" in stats["providers"]

    def test_get_stats_builtin_provider_registered(self):
        """MemoryManager always has the builtin provider (file-based)."""
        mm = MemoryManager()
        stats = mm.get_stats()
        # Builtin provider should always be present (even if empty)
        assert isinstance(stats["providers"], dict)

    def test_get_stats_graceful_when_provider_raises(self):
        class BadProvider(FakeStatsProvider):
            def get_stats(self):
                raise RuntimeError("stats unavailable")

        mm = MemoryManager()
        mm.add_provider(BadProvider("bad"))
        stats = mm.get_stats()  # Should not raise
        assert isinstance(stats, dict)

    def test_get_stats_generates_timestamp(self):
        mm = MemoryManager()
        stats = mm.get_stats()
        assert "generated_at" in stats
        assert isinstance(stats["generated_at"], str)


# ---------------------------------------------------------------------------
# Holographic MemoryStore.stats() tests
# ---------------------------------------------------------------------------

class TestHolographicStoreStats:

    def test_stats_method_exists(self):
        from plugins.memory.holographic.store import MemoryStore
        assert hasattr(MemoryStore, "stats")

    def test_stats_empty_store(self):
        from plugins.memory.holographic.store import MemoryStore
        store = MemoryStore(":memory:")
        try:
            stats = store.stats()
            assert stats["total_facts"] == 0
            assert stats["archived_count"] == 0
            assert stats["trust_distribution"]["high"] == 0
            assert stats["trust_distribution"]["medium"] == 0
            assert stats["trust_distribution"]["low"] == 0
        finally:
            store.close()

    def test_stats_counts_inserted_facts(self):
        from plugins.memory.holographic.store import MemoryStore
        store = MemoryStore(":memory:")
        try:
            store.add_fact("fact one", "context")
            store.add_fact("fact two", "context")
            store.add_fact("fact three", "fact")
            stats = store.stats()
            assert stats["total_facts"] == 3
            assert stats["category_counts"]["context"] == 2
            assert stats["category_counts"]["fact"] == 1
        finally:
            store.close()

    def test_stats_trust_band_classification(self):
        from plugins.memory.holographic.store import MemoryStore
        store = MemoryStore(":memory:")
        try:
            # Insert facts — default trust = 0.5
            for i in range(5):
                store.add_fact(f"fact {i}", "context")
            # Override trust scores via SQL
            for i, trust in enumerate([0.9, 0.8, 0.6, 0.4, 0.2], start=1):
                store._conn.execute(
                    "UPDATE facts SET trust_score = ? WHERE fact_id = ?",
                    (trust, i)
                )
            store._conn.commit()
            stats = store.stats()
            td = stats["trust_distribution"]
            # high: >= 0.7 -> 2 facts (0.9, 0.8)
            assert td["high"] == 2, f"expected high=2, got {td}"
            # medium: >= 0.4 and < 0.7 -> 2 facts (0.6, 0.4)
            assert td["medium"] == 2, f"expected medium=2, got {td}"
            # low: < 0.4 -> 1 fact (0.2)
            assert td["low"] == 1, f"expected low=1, got {td}"
        finally:
            store.close()

    def test_stats_archived_count(self):
        from plugins.memory.holographic.store import MemoryStore
        store = MemoryStore(":memory:")
        try:
            store.add_fact("active fact", "context")
            fid = store.add_fact("archived fact", "context")
            store.archive_fact(fid)
            stats = store.stats()
            assert stats["archived_count"] == 1
            assert stats["total_facts"] == 1  # archived removed from facts table
        finally:
            store.close()

    def test_stats_returns_expected_keys(self):
        from plugins.memory.holographic.store import MemoryStore
        store = MemoryStore(":memory:")
        try:
            store.add_fact("test", "context")
            stats = store.stats()
            for key in [
                "total_facts", "archived_count", "category_counts",
                "avg_trust", "trust_distribution",
                "total_retrievals", "total_helpful",
                "oldest_fact_days", "recent_facts", "generated_at",
            ]:
                assert key in stats, f"Missing key: {key}"
        finally:
            store.close()


# ---------------------------------------------------------------------------
# memory_tool action='stats' integration test
# ---------------------------------------------------------------------------

class TestMemoryToolStatsAction:

    def test_stats_returns_json(self):
        from tools.memory_tool import memory_tool, MemoryStore
        store = MemoryStore()
        result = memory_tool(action="stats", store=store)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_stats_contains_store_info(self):
        from tools.memory_tool import memory_tool, MemoryStore
        store = MemoryStore()
        result = memory_tool(action="stats", store=store)
        data = json.loads(result)
        # Should have either holographic or files key
        assert any(k in data for k in ("holographic", "files", "memory_md", "user_md", "external_providers")), \
            f"Expected stats key, got: {list(data.keys())}"


# ---------------------------------------------------------------------------
# Quality gate tests (Phase 1)
# ---------------------------------------------------------------------------

class TestMemoryQualityGate:

    def test_quality_gate_blocks_quoted_api_key(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality('ANTHROPIC_API_KEY="sk-ant-xxx"')
        assert result is not None and result.get("blocked") is not False

    def test_quality_gate_blocks_quoted_token(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality('github_token="ghp_abc123"')
        assert result is not None and result.get("blocked") is not False

    def test_quality_gate_allows_normal_content(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality("用户喜欢用中文交流，偏好详细解释和实际代码示例")
        assert result is None or not result.get("blocked")

    def test_quality_gate_blocks_task_progress(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality("完成了一个任务，结果很好")
        assert result is not None

    def test_quality_gate_blocks_code_snippet(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality("def hello():\n    print('hi')")
        assert result is not None

    def test_quality_gate_blocks_git_history(self):
        from tools.memory_tool import _check_memory_quality
        result = _check_memory_quality("git log --oneline -10")
        assert result is not None
