# Proxy Contract Audit Report
## Contract Address
- 0xa174a9b694d3271b6192f08d00ba65dad8cc3ecd

## Report Summary
- Date: 2025-06-28

## Proxy Type
- Minimal Proxy(ERC-1167)

## Logic / Facets / Beacon Address
- Logic Contract Address: 0xe2ad2d0469165a386cb734b6921cb2e360f36518

## Selectors Overview
- Number of Selectors in Proxy Contract: 0
- Number of Selectors in Logic Contract: 57

## Storage Layout Overview (Proxy Slot Layout)
> Note: Slots used by mappings or dynamic arrays may not appear explicitly in this layout, as their storage is computed dynamically via keccak(slot . key). Only the base slot of such variables will appear here. Also, some variable's type may remain unkonwn due to insufficient context

---

### Overall Result
| Issue Category                  | Status  | Severity |
|--------------------------------|---------|----------|
| Function Selector Collisions    | Not Found | Low |
| Storage Conflicts               | Not Found | Low |
| Initialization Missing          | Not Found | Low |
| Permission Control Missing      | Found | High |

---

## 1. Function Selector Collision Analysis
- Number of Collisions Found: 0
- Collided Selectors:

---

## 2. Storage Conflict Analysis
- Proxy vs Logic:

---

## 3. Initialization Missing Check
- Initialization Status: INITIALIZED

---

## 4. Permission Control Analysis
- Sensitive Storage Slots:
    - owner → Slot 3 Mask 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
- Detected Permission Check Locations:
    - Selector 0x01306373 → missing → no admin check, no privileged operation detected
    - Selector 0x015af8ee → missing → no admin check, no privileged operation detected
    - Selector 0x079a71ba → missing → no admin check, no privileged operation detected
    - Selector 0x0a85bd01 → missing → no admin check, no privileged operation detected
    - Selector 0x0d45e6f6 → rejected → Privileged function detected, but rejected.
    - Selector 0x0e25569e → missing → no admin check, no privileged operation detected
    - Selector 0x150b7a02 → missing → no admin check, no privileged operation detected
    - Selector 0x21421707 → missing → no admin check, no privileged operation detected
    - Selector 0x22dca8bb → missing → no admin check, no privileged operation detected
    - Selector 0x2b7de7dd → missing → no admin check, no privileged operation detected
    - Selector 0x3187e5a0 → missing → no admin check, no privileged operation detected
    - Selector 0x321d2f92 → missing → no admin check, no privileged operation detected
    - Selector 0x35128b65 → missing → no admin check, no privileged operation detected
    - Selector 0x3543b2c0 → missing → no admin check, no privileged operation detected
    - Selector 0x35981fd8 → missing → no admin check, no privileged operation detected
    - Selector 0x3941aab1 → missing → no admin check, no privileged operation detected
    - Selector 0x42e94c90 → missing → no admin check, no privileged operation detected
    - Selector 0x45a92c96 → passed → admin check passed; owner changed by 0xe2ad2d0469165a386cb734b6921cb2e360f36518
    - Selector 0x4e487b71 → missing → no admin check, no privileged operation detected
    - Selector 0x57091c3f → passed → admin check passed; no privileged operation detected
    - Selector 0x5d222d0f → missing → no admin check, no privileged operation detected
    - Selector 0x5d2dfce5 → missing → no admin check, no privileged operation detected
    - Selector 0x61790a81 → missing → no admin check, no privileged operation detected
    - Selector 0x61a52a36 → missing → no admin check, no privileged operation detected
    - Selector 0x626fce23 → missing → no admin check, no privileged operation detected
    - Selector 0x639d7e86 → missing → no admin check, no privileged operation detected
    - Selector 0x63df72ea → missing → no admin check, no privileged operation detected
    - Selector 0x7ac159af → missing → no admin check, no privileged operation detected
    - Selector 0x7c282ef9 → missing → no admin check, no privileged operation detected
    - Selector 0x8127d479 → missing → no admin check, no privileged operation detected
    - Selector 0x877c86fb → missing → no admin check, no privileged operation detected
    - Selector 0x8823151b → missing → no admin check, no privileged operation detected
    - Selector 0x88786272 → missing → no admin check, no privileged operation detected
    - Selector 0x8a4cfd34 → missing → no admin check, no privileged operation detected
    - Selector 0x8d791478 → missing → no admin check, no privileged operation detected
    - Selector 0x995330a7 → missing → no admin check, no privileged operation detected
    - Selector 0xa4c015cc → passed → admin check passed; no privileged operation detected
    - Selector 0xa9059cbb → missing → no admin check, no privileged operation detected
    - Selector 0xaa6ca808 → missing → no admin check, no privileged operation detected
    - Selector 0xac7c420e → missing → no admin check, no privileged operation detected
    - Selector 0xb321a7a9 → missing → owner write detected in logic 0xe2ad2d0469165a386cb734b6921cb2e360f36518
    - Selector 0xbe72f3f8 → missing → no admin check, no privileged operation detected
    - Selector 0xc3124525 → missing → no admin check, no privileged operation detected
    - Selector 0xc3a78bdb → missing → no admin check, no privileged operation detected
    - Selector 0xc4f45423 → missing → no admin check, no privileged operation detected
    - Selector 0xc57981b5 → missing → no admin check, no privileged operation detected
    - Selector 0xc7d89478 → passed → admin check passed; no privileged operation detected
    - Selector 0xd2845977 → missing → no admin check, no privileged operation detected
    - Selector 0xd32521a0 → rejected → Privileged function detected, but rejected.
    - Selector 0xd8270dce → missing → no admin check, no privileged operation detected
    - Selector 0xda25de3c → missing → no admin check, no privileged operation detected
    - Selector 0xe21db255 → missing → no admin check, no privileged operation detected
    - Selector 0xe29eb836 → missing → no admin check, no privileged operation detected
    - Selector 0xed196eee → missing → no admin check, no privileged operation detected
    - Selector 0xef58f9e7 → missing → no admin check, no privileged operation detected
    - Selector 0xf5aa2edd → missing → no admin check, no privileged operation detected
    - Selector 0xf8dd0126 → missing → no admin check, no privileged operation detected

---

## 5. Final Assessment
**Overall Security Posture**: Needs Improvement
**Recommendation**: Needs fixes

---
