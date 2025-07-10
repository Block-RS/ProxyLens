# ProxyLens

**ProxyLens** is a lightweight and practical bytecode-level tool for analyzing Ethereum proxy contracts. It supports detection of Transparent, UUPS, Minimal, Beacon, and Diamond proxies, and includes built-in support for delegatecall tracking, storage slot inference, and vulnerability detection.


## 🛡️ Supported Vulnerability Types

-   Storage Collision
-   Selector Collision
-   Missing Initialization
-   Missing Access Control


## 📦 Environment Requirements

- Python >= 3.10 (recommended: 3.10–3.11)


## 🚀 Quick Start
```bash
python proxylens.py <contract_address>
```

## 🧠 Project Architecture
```
ProxyLens/
├── proxylens.py                     # Main entry point
├── config.py                        # Configuration (e.g., RPC URL, API keys)
├── contracts_with_delegatecall.json
├── output/                          # Output folder for results
├── tests/                           # Unit tests
│   └── test_for_multiple_mapping_arraying.py
├── tools/                           # Utilities and heuristics
│   ├── utils.py
│   └── oracles.py
├── octopus/                         # Octopus symbolic EVM emulator
│   ├── arch/                        # EVM and WASM disassemblers
│   ├── core/                        # SSA, storage, memory, and CFG logic
│   ├── engine/                      # Emulator and execution engine
│   └── platforms/ETH/              # Ethereum-specific modules
```

-   octopus/: Self-contained symbolic execution engine with custom EVM instruction handling.

-   tools/oracles.py: Implements proxy pattern detection logic.

-   proxylens.py: Combines all components into a single orchestrated analysis workflow.


## 📝 Contact
If you have any questions or suggestions, please feel free to contact:
📧 honghaojia@cug.edu.com