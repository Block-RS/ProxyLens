# Proxy Contract Audit Report
## Contract Address
- 0xede059573fd41d9b39fadc0e9a6f83e228ba1b4e

## Report Summary
- Date: 2025-06-19

## Proxy Type
- Customized

## Logic / Facets / Beacon Address
- Logic Contract Address: 0x125f839bb972a1fc6c352e0eecfac4d99a8e8c98

## Selectors Overview
- Number of Selectors in Proxy Contract: 0
- Number of Selectors in Logic Contract: 69

## Storage Layout Overview (Proxy Slot Layout)
> Note: Slots used by mappings or dynamic arrays may not appear explicitly in this layout, as their storage is computed dynamically via keccak(slot . key). Only the base slot of such variables will appear here. Also, some variable's type may remain unkonwn due to insufficient context
    - Slot 89532207833283453166981358064394884954800891875771469636219037672473505217783 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: address
    - Slot 1 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: uint256
    - Slot 2 Mask 0x00000000000000000000000000000000000000000000000000000000000000ff → Type: uint8
    - Slot 0 Mask 0x0000000000000000000000ff0000000000000000000000000000000000000000 → Type: bool
    - Slot 0 Mask 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff → Type: address
    - Slot 5 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown
    - Slot 9 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown
    - Slot 11 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: uint256
    - Slot 4 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown
    - Slot 3 Mask 0x00000000000000000000000000000000000000000000000000000000000000ff → Type: uint8
    - Slot 8 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown
    - Slot 7 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: unknown
    - Slot 12 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: mapping(unknown => unknown)
    - Slot 10 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: mapping(unknown => mapping(unknown => unknown))
    - Slot 13 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: mapping(unknown => unknown)
    - Slot 14 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff → Type: mapping(unknown => unknown)

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
    - logic_address → Slot 89532207833283453166981358064394884954800891875771469636219037672473505217783 Mask 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
- Detected Permission Check Locations:
    - Selector 0x0290cbc8 → missing → no admin check, no privileged operation detected
    - Selector 0x0305da4f → missing → no admin check, no privileged operation detected
    - Selector 0x039ab887 → missing → no admin check, no privileged operation detected
    - Selector 0x054ab01a → missing → no admin check, no privileged operation detected
    - Selector 0x06fdde03 → missing → no admin check, no privileged operation detected
    - Selector 0x095ea7b3 → missing → no admin check, no privileged operation detected
    - Selector 0x10f3a6d8 → missing → no admin check, no privileged operation detected
    - Selector 0x13e23e41 → missing → no admin check, no privileged operation detected
    - Selector 0x158ef93e → missing → no admin check, no privileged operation detected
    - Selector 0x17a1a861 → missing → no admin check, no privileged operation detected
    - Selector 0x18160ddd → missing → no admin check, no privileged operation detected
    - Selector 0x182df0f5 → missing → no admin check, no privileged operation detected
    - Selector 0x1cda95d5 → missing → no admin check, no privileged operation detected
    - Selector 0x226e835c → missing → no admin check, no privileged operation detected
    - Selector 0x23b872dd → missing → no admin check, no privileged operation detected
    - Selector 0x28cdfaeb → missing → no admin check, no privileged operation detected
    - Selector 0x2f2ba814 → missing → no admin check, no privileged operation detected
    - Selector 0x2f4350c2 → missing → no admin check, no privileged operation detected
    - Selector 0x313ce567 → missing → no admin check, no privileged operation detected
    - Selector 0x33a581d2 → missing → no admin check, no privileged operation detected
    - Selector 0x388c0b8c → missing → no admin check, no privileged operation detected
    - Selector 0x3e20a929 → missing → no admin check, no privileged operation detected
    - Selector 0x46951954 → passed → admin check passed; no privileged operation detected
    - Selector 0x4929fbf7 → missing → no admin check, no privileged operation detected
    - Selector 0x496cc164 → missing → no admin check, no privileged operation detected
    - Selector 0x4d12d4b6 → missing → no admin check, no privileged operation detected
    - Selector 0x4fd7c0dd → missing → no admin check, no privileged operation detected
    - Selector 0x52d1902d → missing → no admin check, no privileged operation detected
    - Selector 0x556043ef → missing → no admin check, no privileged operation detected
    - Selector 0x5cde5055 → missing → no admin check, no privileged operation detected
    - Selector 0x5e5c06e2 → missing → no admin check, no privileged operation detected
    - Selector 0x63152a50 → missing → no admin check, no privileged operation detected
    - Selector 0x6b4169c3 → missing → no admin check, no privileged operation detected
    - Selector 0x6eb1769f → missing → no admin check, no privileged operation detected
    - Selector 0x6f307dc3 → missing → no admin check, no privileged operation detected
    - Selector 0x70a08231 → missing → no admin check, no privileged operation detected
    - Selector 0x715018a6 → passed → admin check passed; owner changed by 0x125f839bb972a1fc6c352e0eecfac4d99a8e8c98
    - Selector 0x71ee46eb → missing → no admin check, no privileged operation detected
    - Selector 0x77ede051 → missing → no admin check, no privileged operation detected
    - Selector 0x81c8d895 → missing → no admin check, no privileged operation detected
    - Selector 0x84d4b410 → missing → no admin check, no privileged operation detected
    - Selector 0x852a12e3 → missing → no admin check, no privileged operation detected
    - Selector 0x8da5cb5b → missing → no admin check, no privileged operation detected
    - Selector 0x8f32d59b → passed → admin check passed; no privileged operation detected
    - Selector 0x95d89b41 → missing → no admin check, no privileged operation detected
    - Selector 0x9c52da7a → missing → no admin check, no privileged operation detected
    - Selector 0xa0712d68 → missing → no admin check, no privileged operation detected
    - Selector 0xa3a7e7f3 → missing → no admin check, no privileged operation detected
    - Selector 0xa6afed95 → missing → no admin check, no privileged operation detected
    - Selector 0xa9059cbb → missing → no admin check, no privileged operation detected
    - Selector 0xb2bdfa7b → missing → no admin check, no privileged operation detected
    - Selector 0xb5dbfc1a → missing → no admin check, no privileged operation detected
    - Selector 0xbf5bfdfb → missing → no admin check, no privileged operation detected
    - Selector 0xc034d0db → missing → no admin check, no privileged operation detected
    - Selector 0xc17693c0 → missing → no admin check, no privileged operation detected
    - Selector 0xc1a2007d → missing → no admin check, no privileged operation detected
    - Selector 0xc200659e → missing → no admin check, no privileged operation detected
    - Selector 0xc4a11628 → missing → no admin check, no privileged operation detected
    - Selector 0xd007c644 → missing → no admin check, no privileged operation detected
    - Selector 0xd271be3f → missing → no admin check, no privileged operation detected
    - Selector 0xd3ac25c4 → passed → admin check passed; no privileged operation detected
    - Selector 0xd8884795 → missing → no admin check, no privileged operation detected
    - Selector 0xdb006a75 → missing → no admin check, no privileged operation detected
    - Selector 0xdd62ed3e → missing → no admin check, no privileged operation detected
    - Selector 0xe192782b → missing → no admin check, no privileged operation detected
    - Selector 0xf04bf8b3 → missing → no admin check, no privileged operation detected
    - Selector 0xf2fde38b → passed → admin check passed; owner changed by 0x125f839bb972a1fc6c352e0eecfac4d99a8e8c98
    - Selector 0xfc0c546a → missing → no admin check, no privileged operation detected
    - Selector 0xfdbbf8ac → missing → no admin check, no privileged operation detected

---

## 5. Final Assessment
**Overall Security Posture**: Good
**Recommendation**: Safe to deploy

---
