# Proxy Contract Audit Report
## Contract Address
- 0xd3954a8fcdf90db6018cc2d0b96b77e88a749363

## Report Summary
- Date: 2025-06-15

## Proxy Type
- Beacon Proxy

## Logic / Facets / Beacon Address
- Beacon Contract Address: 0x9f3cfe030164651b055331cd02fb4b4a05c66835
- Logic Contract Address: 0xceb5856c525bbb654eea75a8852a0f51073c4a58

## Selectors Overview
- Number of Selectors in Proxy Contract: 1
- Number of Selectors in Logic Contract: 26
- Number of Selectors in Beacon Contract: 5

## Storage Layout Overview (Proxy Slot Layout)
> Note: Slots used by mappings or dynamic arrays may not appear explicitly in this layout, as their storage is computed dynamically via keccak(slot . key). Only the base slot of such variables will appear here. Also, some variable's type may remain unkonwn due to insufficient context
    - Slot 0 Mask 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff → Type: address
    - Slot 1 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown

---

### Overall Result
| Issue Category                  | Status  | Severity |
|--------------------------------|---------|----------|
| Function Selector Collisions    | Not Found | Low |
| Storage Conflicts               | Not Found | Low |
| Initialization Missing          | Not Found | Low |
| Permission Control Missing      | Not Found | Low |

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
    - owner → Slot 0 Mask 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    - logic_address → Slot 1 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
- Detected Permission Check Locations:
    - Selector 0x3659cfe6 → passed → admin check passed; no privileged operation detected
    - Selector 0x5c60da1b → missing → no admin check, no privileged operation detected
    - Selector 0x715018a6 → passed → admin check passed; owner changed by 0x9f3cfe030164651b055331cd02fb4b4a05c66835
    - Selector 0x8da5cb5b → missing → no admin check, no privileged operation detected
    - Selector 0xf2fde38b → passed → admin check passed; owner changed by 0x9f3cfe030164651b055331cd02fb4b4a05c66835

---

## 5. Final Assessment
**Overall Security Posture**: Good
**Recommendation**: Safe to deploy

---
