---
name: hermes-holographic-memory
description: Hermes holographic memory plugin — SQLite-backed fact store with FTS5, HRR vectors, trust scoring, and entity resolution. Optional Phase 2+ memory layer.
triggers:
  - 记忆增强
  - 长期记忆
  - 向量检索
  - 结构化记忆
  - holographic
---

# Hermes Holographic Memory Plugin

## 核心概念
Holographic 是 Hermes 的**可选高级记忆插件**，位于 `plugins/memory/holographic/`（1777行），需要 `memory.provider: holographic` 在 config.yaml 中激活。

## 文件结构
- `holographic.py`（203行）— HRR（Nested/Reduced Representations）向量代数，circular convolution/deconvolution，NumPy 可选（无 NumPy 时自动降级为 FTS5 + Jaccard）
- `store.py`（574行）— `MemoryStore` 类：add_fact、get_fact、update_trust、extract_entities、add_entity，FTS5 索引与触发器
- `retrieval.py`（593行）— `FactRetriever` 类：hybrid search pipeline、_jaccard_similarity、_temporal_decay
- `__init__.py`（407行）— 插件注册、`HolographicMemoryProvider`、`FACT_STORE_SCHEMA`、`FACT_FEEDBACK_SCHEMA`

## 两大记忆系统对比

| 维度 | 基础记忆（MEMORY.md） | Holographic（SQLite） |
|------|---------------------|---------------------|
| 存储容量 | 2,200 字符硬限制 | 无限制 |
| 检索方式 | 全量注入 system prompt | 按需检索（prefetch） |
| 搜索能力 | ❌ | ✅ FTS5 + HRR 向量 |
| 实体关联 | ❌ | ✅ 实体图谱 |
| 矛盾检测 | ❌ | ✅ 自动检测 |
| 可信度学习 | ❌ | ✅ Trust score |
| 时间衰减 | ❌ | ✅ Temporal decay |

## 启用步骤
1. 阅读 `plugins/memory/holographic/README.md` 完整配置说明
2. config.yaml 设置 `memory.provider: holographic`
3. 可选配置：`memory.db_path`、`memory.auto_extract: true`、`memory.default_trust: 0.5`、`memory.min_trust_threshold: 0.3`、`memory.hrr_dim: 1024`

## 核心工具
- `fact_store`（9个action）：add / search / probe / related / reason / contradict / update / remove / list
  - `probe`：给定实体名，检索该实体所有相关事实（用于记忆查询）
  - `contradict`：检测矛盾事实对
  - `reason`：多实体组合推理查询
- `fact_feedback`：positive/negative/neutral 三种反馈，影响 trust score（+0.05/-0.10）

## Phase 2 完整配置（已验证）
```yaml
memory:
  provider: holographic

plugins:
  hermes-memory-store:
    db_path: $HERMES_HOME/memory_store.db
    auto_extract: true          # Session 结束时自动提取偏好和决策
    default_trust: 0.5
    min_trust_threshold: 0.3
    temporal_decay_half_life: 0  # 天数，0=禁用
    hrr_dim: 1024
    hrr_weight: 0.3
```

## 已验证功能（2026-04-24）
- fact_store add/search/probe/list/update/remove ✅
- fact_feedback helpful/unhelpful ✅
- contradiction detection ✅
- on_memory_write hook（builtin → holographic 镜像）✅
- auto_extract 模式 ✅
- prefetch 机制 ✅
- system_prompt_block 动态摘要 ✅

## 已知限制

### FTS5 中文 tokenization 边界
FTS5 对纯中文按字符分词，`search('中文')` 可以匹配"中文交流"，但 `search('中文交流')` 可能匹配不到"中文"。**解法**：用单个字符查询，或用 `probe('用户')` 实体召回代替关键词搜索。

### Jaccard 中文权重为 0
FTS5 对中文按字符 tokenization，而 Jaccard similarity 用空格/标点分词。中文内容的 Jaccard 交集通常为空（score=0）。**影响有限**：trust 分数权重（默认 0.5 × 0.5 = 0.25）会兜底排序。

## 推荐实践
- 两者并存：MEMORY.md 做 system prompt 快照（快速、低开销），holographic 做深度检索（结构化、可信度）
- 优先 probe/reason 检索，而非全量注入，降低 token 消耗
- `auto_extract: true` 让 agent 自动从对话历史中提取偏好和决策
- `fact_feedback` 可在每次成功使用事实后调用，逐步训练 trust 分数
