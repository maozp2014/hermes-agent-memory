---
name: plan
description: Plan mode for Hermes — inspect context, write a structured implementation plan, and do NOT execute until the user confirms.
version: 2.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [planning, plan-mode, implementation, workflow]
    related_skills: [writing-plans, subagent-driven-development]
---

# Plan Mode

Use this skill when the user wants a plan instead of execution — for new features, architectural changes, complex refactoring, or any task that warrants structured thinking before action.

## Core behavior

For this turn, you are planning only.

- Do NOT implement code.
- Do NOT edit project files except the plan markdown file.
- Do NOT run mutating terminal commands, commit, push, or perform external actions.
- You MAY inspect the repo or other context with read-only commands/tools when needed.
- Your deliverable is a structured markdown plan saved inside the active workspace under `.hermes/plans/`.
- **CRITICAL: Wait for explicit user confirmation ("yes", "proceed", or similar) before taking any action.**

## When to use

Use `/plan` when:
- Starting a new feature
- Making significant architectural changes
- Working on complex refactoring
- Multiple files/components will be affected
- Requirements are unclear or ambiguous

## Interaction style

- If the request is clear enough, write the plan directly.
- If no explicit instruction accompanies `/plan`, infer the task from the current conversation context.
- If it is genuinely underspecified, ask a brief clarifying question instead of guessing.
- After saving the plan, reply briefly with a summary and the saved path.

---

## Standard Plan Format

Every plan should include these seven sections. Adjust scope to the actual task — not every section needs full treatment for simple tasks, but none should be silently skipped.

### 1. Overview

2-3 sentence summary of what this plan addresses and why it matters.

### 2. Requirements

Unambiguous list of what must be true when the work is done. Each requirement should be independently verifiable.

- [Requirement 1]
- [Requirement 2]

### 3. Architecture Changes

List files to be created, modified, or deleted, with a brief description of each change.

- **New**: `src/services/notification.ts` — notification service with queue
- **Modify**: `src/models/user.ts` — add notification preferences field
- **Delete**: `src/utils/old-notifier.ts` — replaced by new service

### 4. Implementation Steps

Break the work into phases. Each phase should be independently deliverable and mergeable. Each step should be:

- Specific and actionable
- Include the exact file path(s)
- State dependencies (None / Requires step X)
- Include a Risk rating: **Low** / **Medium** / **High**

#### Phase 1: [Phase Name] (N files)

1. **[Step Name]** (File: `path/to/file.ext`)
   - **Action**: What to do
   - **Why**: Reason this step comes here
   - **Dependencies**: None / Requires step X
   - **Risk**: Low | Medium | High

2. **[Step Name]** (File: `path/to/file.ext`)
   ...

#### Phase 2: [Phase Name] (N files)

...

#### Phase 3: [Phase Name] (N files)

...

### 5. Testing Strategy

- **Unit tests**: [files or modules to unit test]
- **Integration tests**: [flows to integration test]
- **E2E tests**: [user journeys or critical paths]
- **Coverage gate**: Target ≥ 80% coverage on changed code

### 6. Risks & Mitigations

For each identified risk, provide a specific mitigation.

- **Risk**: [Description of the risk]
  - **Mitigation**: [Specific action to reduce or eliminate the risk]
- **Risk**: Webhook events arrive out of order
  - **Mitigation**: Use event timestamps; idempotent updates with `INSERT ... ON CONFLICT DO UPDATE`

### 7. Success Criteria

Checklist of verifiable outcomes. Each criterion should be testable or directly observable.

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] All existing tests still pass

---

## Red Flags Checklist

Before finalizing the plan, scan for these common issues and address them in the Risks section:

- ⚠️ **Large functions (>50 lines)** — break into smaller, focused functions
- ⚠️ **Deep nesting (>4 levels)** — extract branches or use early returns
- ⚠️ **Duplicated code** — extract shared utilities or base classes
- ⚠️ **Missing error handling** — every external call needs a fallback
- ⚠️ **Hardcoded values** — use config/env variables
- ⚠️ **Missing tests** — add tests for all new logic
- ⚠️ **Performance bottlenecks** — check N+1 queries, unbounded loops
- ⚠️ **No testing strategy** — every plan needs explicit test coverage
- ⚠️ **Steps without file paths** — every step should name files
- ⚠️ **Phases that can't be delivered independently** — restructure so each phase works on its own

---

## Phased Delivery Pattern

For larger features, structure delivery in three phases:

- **Phase 1: MVP** — Smallest slice that provides value. Can be shipped and used independently.
- **Phase 2: Core Experience** — Complete the happy-path user journey.
- **Phase 3: Edge Cases** — Error handling, boundary conditions, polish.

Each phase should be independently mergeable. Avoid plans requiring all phases before anything works.

---

## Worked Example: Stripe Subscription Billing

Below is the level of detail expected for a medium-complexity feature.

---

# Implementation Plan: Stripe Subscription Billing

## Overview

Add subscription billing with three tiers (Free/Pro/Enterprise). Users upgrade via Stripe Checkout, and webhook events keep subscription status in sync. Feature gates enforce tier limits.

## Requirements

- Three tiers: Free (default), Pro ($29/mo), Enterprise ($99/mo)
- Stripe Checkout for the payment flow (server-side session creation)
- Webhook handler for subscription lifecycle events (created, updated, deleted)
- Feature gating based on subscription tier (server-side enforcement)
- Subscription status UI in user profile

## Architecture Changes

- **New**: `supabase/migrations/004_subscriptions.sql` — subscriptions table
- **New**: `src/app/api/checkout/route.ts` — Stripe Checkout session creation
- **New**: `src/app/api/webhooks/stripe/route.ts` — webhook event handler
- **New**: `src/middleware.ts` — tier-based route protection
- **New**: `src/components/PricingTable.tsx` — pricing page with upgrade buttons
- **Modify**: `src/models/user.ts` — add subscription fields
- **Delete**: `src/utils/old-billing.ts` — replaced by new Stripe integration

## Implementation Steps

### Phase 1: Database & Webhooks (2 files)

1. **Create subscriptions migration** (File: `supabase/migrations/004_subscriptions.sql`)
   - **Action**: `CREATE TABLE subscriptions (id, user_id, stripe_customer_id, stripe_subscription_id, status, tier, created_at)` with RLS policies
   - **Why**: Store billing state server-side — never trust the client
   - **Dependencies**: None
   - **Risk**: Low

2. **Create Stripe webhook handler** (File: `src/app/api/webhooks/stripe/route.ts`)
   - **Action**: Handle `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`. Verify Stripe signature. Idempotent updates using event ID.
   - **Why**: Keep subscription status in sync with Stripe's source of truth
   - **Dependencies**: Step 1 (needs subscriptions table)
   - **Risk**: **High** — webhook signature verification is critical; test with Stripe CLI

### Phase 2: Checkout Flow (2 files)

3. **Create checkout API route** (File: `src/app/api/checkout/route.ts`)
   - **Action**: Create Stripe Checkout session with `price_id`, `success_url`, `cancel_url`. Validate user is authenticated.
   - **Why**: Server-side session creation prevents client-side price tampering
   - **Dependencies**: Step 1
   - **Risk**: Medium — must validate authenticated user before creating session

4. **Build pricing page** (File: `src/components/PricingTable.tsx`)
   - **Action**: Display three tiers with feature comparison matrix and upgrade buttons
   - **Why**: User-facing upgrade flow
   - **Dependencies**: Step 3 (needs checkout endpoint)
   - **Risk**: Low

### Phase 3: Feature Gating (1 file)

5. **Add tier-based middleware** (File: `src/middleware.ts`)
   - **Action**: On protected routes, query subscription status. Redirect free users from Pro-tier features with an upgrade prompt.
   - **Why**: Enforce tier limits server-side — client-side gating is cosmetic only
   - **Dependencies**: Steps 1-2 (needs subscription data in DB)
   - **Risk**: Medium — must handle `expired`, `past_due`, `canceled` states explicitly

## Testing Strategy

- **Unit tests**: Webhook event parsing logic, tier-checking utility functions
- **Integration tests**: Checkout session creation flow, webhook processing
- **E2E tests**: Full upgrade flow using Stripe test mode (use `stripe CLI listen --forward-to localhost:3000/api/webhooks/stripe`)
- **Coverage gate**: ≥ 80% on `src/app/api/webhooks/stripe/route.ts` and `src/middleware.ts`

## Risks & Mitigations

- **Risk**: Webhook events arrive out of order (e.g., `subscription.deleted` before `subscription.updated`)
  - **Mitigation**: Use Stripe event timestamps; idempotent updates with `INSERT ... ON CONFLICT DO UPDATE`; log ordering anomalies
- **Risk**: User upgrades but webhook fails to deliver (network issue, Stripe retry exhaustion)
  - **Mitigation**: Poll Stripe subscription status as a fallback; show "processing" state in UI; add a manual sync button in admin panel
- **Risk**: Email deliverability for notification emails
  - **Mitigation**: Configure SPF/DKIM before launch; use Stripe's email receipts for billing emails

## Success Criteria

- [ ] User can upgrade from Free to Pro via Stripe Checkout (test in Stripe dashboard)
- [ ] Webhook correctly syncs subscription status on `updated` and `deleted` events
- [ ] Free users cannot access Pro-tier features (verified by E2E test)
- [ ] Expired subscriptions are correctly downgraded
- [ ] All unit and integration tests pass with ≥ 80% coverage on new files
- [ ] Existing tests still pass (no regression)

---

## Save location

Save the plan with `write_file` under:
- `.hermes/plans/YYYY-MM-DD_HHMMSS-<slug>.md`

Treat that as relative to the active working directory / backend workspace. Hermes file tools are backend-aware, so using this relative path keeps the plan with the workspace on local, docker, ssh, modal, and daytona backends.

If the runtime provides a specific target path, use that exact path.
If not, create a sensible timestamped filename yourself under `.hermes/plans/`.
