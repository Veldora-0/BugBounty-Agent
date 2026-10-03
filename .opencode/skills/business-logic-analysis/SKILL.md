---
name: business-logic-analysis
description: Business logic analysis, workflow sequence abuse, state machine flaws, and race condition evaluation.
---

# Business Logic Analysis Methodology

## Core Objective
Identify vulnerabilities arising from design oversights, incorrect operational assumptions, or unvalidated state transitions that cannot be detected by automated scanners.

## Core Focus Areas
1. **Workflow Sequence & Step Skipping**:
   * Multi-step wizards (checkout, registration, verification): can step 3 be accessed directly without completing step 2?
   * Can verification codes or confirmation steps be bypassed by manipulating URL or state tokens?
2. **Numeric & Quantity Invariants**:
   * Negative numbers in cart quantities or transfer amounts (`quantity: -1`).
   * Fractional currency or rounding exploitation.
   * Integer overflow or extremely large quantities.
3. **Race Conditions & Concurrency**:
   * Single-use coupons or referral rewards redeemed simultaneously via parallel threads.
   * Double-spend or double-withdrawal race conditions.
4. **Trust Boundary Assumptions**:
   * Trusting client-supplied pricing or discount codes sent in the request body.

## Safety & Real-World Impact Boundary
* **NEVER** trigger real monetary charges on unowned credit cards or real external financial institutions.
* Test only with test-mode credentials, coupon codes created for research, or micro-transactions explicitly authorized by the program.
