# config.py
NETWORK = "mainnet"  # 可选: "mainnet", "sepolia"

NETWORK_RPC_URLS = {
    "mainnet": "https://mainnet.infura.io/v3/ebec0b91a8a943ab8de8576000e5b9a9",
    "sepolia": "https://sepolia.infura.io/v3/ebec0b91a8a943ab8de8576000e5b9a9"
}

ETHERSCAN_API_BASE = {
    "mainnet": "https://api.etherscan.io",
    "sepolia": "https://api-sepolia.etherscan.io"
}

ETHERSCAN_API_KEY = "TP39PR5ZZTJB7MQY8VUGG5IK14FV4YJHNB"

RPC_URL = NETWORK_RPC_URLS[NETWORK]
ETHERSCAN_BASE = ETHERSCAN_API_BASE[NETWORK]
