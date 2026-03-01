# Secret Note 1: Proprietary AI & Quorum Algorithms
**WARNING: HIGHLY CLASSIFIED. DO NOT DISTRIBUTE.**

This document details the mathematical functions and theoretical concepts that make the AI Engine unbreakable. If an attacker knows these exact derivations, they can mathematically "slide" their malware under the thresholds.

## 1. The Immutable State Anchor (Boiling Frog Defense)
To prevent adversarial data poisoning where a hacker slowly trains the AI over 6 months to accept 1,000,000 packets/sec as "normal", we implemented an **Immutable State Anchor**.
- **Logic:** `prof.anchor_pkt_rate = features.pkt_rate.max(10.0);`
- **Execution:** When an IP connects, the very first 60 seconds are locked in memory (or fetched from `ai_profiles_snapshot.json`). The AI will adapt via `Exponential Moving Average (EMA) 0.95 vs 0.05`, but it mathematically *clamps* the upper limit to `max_learning_multiplier` (default `3.0x`). Even if an attacker pumps traffic for a year, the equation physically prevents the baseline from exceeding `300%` of the Anchor.

## 2. Hardware Entropy Polymorphic Quorums
To prevent a hacker from attacking 2 nodes and forging a 2-node Swarm Consensus (Split-Brain fake-block injection), we use hardware entropy to randomize the required voting threshold.
- **Logic:** `hardware_entropy = std::time::SystemTime::now().subsec_nanos()`
- **Execution:** We take the exact sub-millisecond arrival time of the network packet and perform a modulo operation `(hardware_entropy % 2)`. This means the required passing quorum dynamically mutates between `Quorum` and `Quorum + 1` instantly based on quantum timing differences that the hacker cannot predict. 

## 3. Shadow Mode Adaptive Trust Discount
To prevent false-positive blocks on completely safe, high-volume internal developers:
- **Execution:** If `alert_count == 0` and the connection age `> 60 seconds`, the total resulting AI threat score is dynamically slashed by 25% (`score *= 0.75`). This is known internally as the `Adaptive Trust Discount`. It is the core reason Rudras operates almost silently in Client-Mode.
