# Business Logic Review

#### When to use this file

Use this file when the diff touches payments, checkout, pricing, wallets, credits, balances, coupons and promotions, inventory, quotas, trials, seats and invitations, approvals, refunds, transfers, provisioning, or any multi-step workflow.

It covers the `LOGIC` domain (A06:2025 Insecure Design, ASVS V2 and V15). Static pattern scanners cannot infer what your product is supposed to allow: business logic review compares the code against domain invariants taken from the ticket, product documentation, tests, and existing code. When the intended rule is unclear, ask a human instead of guessing. Use [IDENTITY-AND-ACCESS.md](IDENTITY-AND-ACCESS.md) for who may perform an action and [INPUT-API-AND-FILES.md](INPUT-API-AND-FILES.md) for input syntax.

## Core discipline (include in every reviewer prompt for this file)

```
- Write the invariant first ("an order ships only after payment is captured", "a coupon is redeemed once per account"), then look for a path that violates it.
- The server owns state, prices, totals, and limits. Anything the client sends is a claim.
- Every check-then-act sequence on shared state needs atomicity.
- Every entry point that produces the same business effect enforces the same rule.
- Business intent belongs to humans. When the rule itself is ambiguous, record a business_logic human_review question.
```

## LOGIC — Business Logic and Concurrency Controls · A06:2025 · ASVS V2 · V15 (subagent_type: `general`)

Cheat sheets: Business Logic Security, Transaction Authorization, Third Party Payment Gateway Integration.

**LOGIC-01 — Server-Enforced Workflow State Machines**
- **Check:** Multi-step processes (such as `cart -> payment_pending -> paid -> fulfilled`) validate legal state transitions server-side on every mutation.
- **Why:** Attackers invoke finalization endpoints directly out of sequence to skip payment or approval steps.
- **Ref:** `A06:2025` · `ASVS V2` · `CWE-841`
- **Verify:** Identify the states and allowed transitions for the workflow the diff touches. Each mutation checks the current state on the server, atomically, before transitioning, and finalization endpoints (`/confirm`, `/fulfill`, `/approve`, `/complete`) reject out-of-order calls.

**LOGIC-02 — Domain Boundary Checks on Quantities and Amounts**
- **Check:** Monetary values, item counts, and transfer amounts reject negative numbers, zero (where invalid), NaN, and integer overflows.
- **Why:** Submitting a quantity of `-5` in an unguarded checkout calculation turns a debit into an account credit.
- **Ref:** `A06:2025` · `ASVS V2` · `CWE-20` · `CWE-1284`
- **Verify:** Check every new numeric input that affects money, quantity, credits, or limits: reject negatives, zero where invalid, `NaN` and `Infinity`, overflow, and excess precision. Money uses decimals or integer minor units, never floats, and prices and totals are recomputed on the server instead of trusted from the client.

**LOGIC-03 — Atomic Concurrency on Balances and Quotas**
- **Check:** Wallet debits, coupon redemptions, and inventory decrements use database transactions with row-level locking (`SELECT ... FOR UPDATE`) or atomic conditional updates.
- **Why:** Parallel race-condition requests ("double-spend" Time-of-Check to Time-of-Use, or TOCTOU) drain balances multiple times before state commits.
- **Ref:** `A06:2025` · `ASVS V15` · `CWE-362` · `CWE-367`
- **Verify:** Find read-modify-write sequences on balances, stock, coupon usage, quotas, and seat counts. Expect `SELECT ... FOR UPDATE`, optimistic version checks, or a single conditional update (`UPDATE ... SET balance = balance - $1 WHERE id = $2 AND balance >= $1`), plus a unique constraint for one-time redemptions.

**LOGIC-04 — Idempotency and Replay Protection**
- **Check:** Payment captures, fund transfers, and provisioning endpoints require client idempotency keys or single-use nonces.
- **Why:** Network retries or intentional request replays duplicate financial side effects without idempotency enforcement.
- **Ref:** `A06:2025` · `ASVS V2`
- **Verify:** Confirm capture, transfer, refund, order-creation, and provisioning endpoints accept an idempotency key stored under a unique constraint with the original response, or a single-use nonce, and that webhook handlers deduplicate by event ID.

**LOGIC-05 — Cross-Endpoint Business Limit Enforcement**
- **Check:** Free-trial caps, promotional codes, and seat invitation limits enforce quotas in a shared domain layer across REST, GraphQL, and batch endpoints alike.
- **Why:** Quotas enforced only on the primary web controller get bypassed through mobile or batch API routes.
- **Ref:** `API6:2023`
- **Verify:** Locate where each limit is enforced. It must live in the shared domain or service layer that every entry point calls (REST, GraphQL, mobile, batch, import, admin API, webhook), not in one controller.

A race-condition red flag, and its atomic replacement:

```python
# RED FLAG: check-then-act without a lock lets parallel requests spend the same balance twice
wallet = db.query(Wallet).filter(Wallet.id == wallet_id, Wallet.owner_id == principal.user_id).one()
if wallet.balance >= amount:
    wallet.balance -= amount
    db.commit()

# SECURE: amount validated as a positive Decimal upstream (LOGIC-02), then one conditional update;
# zero updated rows means insufficient funds or a concurrent spend
result = db.execute(
    update(Wallet)
    .where(Wallet.id == wallet_id, Wallet.owner_id == principal.user_id, Wallet.balance >= amount)
    .values(balance=Wallet.balance - amount)
)
if result.rowcount != 1:
    db.rollback()
    raise HTTPException(status_code=409, detail="Insufficient funds")
db.commit()
```

## Review moves (apply across the above)

- Draw the state machine and mark which endpoint performs each transition. Try every transition from every other state, including after cancellation, refund, and expiry.
- Run a parallel-request thought experiment on every read-modify-write: two identical requests arrive within the same millisecond.
- Search for every entry point to the same effect (REST, GraphQL, mobile, batch, import, admin, webhook, scheduled job) and compare the limits each one applies.
- Probe boundary values: -1, 0, 0.001, the maximum integer plus one, `NaN`, very large quantities, currency mismatches, and rounding.
- Replay: the same request twice, out of order, after cancellation, and after a refund.

## Validation rules (apply before reporting ANY finding here)

1. State the violated invariant and where it comes from (ticket, documentation, tests, or existing code).
2. Show the concrete abuse sequence and its effect on money, credits, inventory, or access, using dummy accounts only.
3. A race condition needs a plausible interleaving under the transaction and isolation configuration visible in the repository. If the decisive database setting is not in the repository, use `needs_validation`.
4. When the intended rule is ambiguous, record `needs_validation` and a `business_logic` human_review question rather than deciding the rule yourself.
5. Calibrate by financial or access impact: free goods or arbitrary credits are `high`; bounded abuse is `medium`; nuisance is `low`.
