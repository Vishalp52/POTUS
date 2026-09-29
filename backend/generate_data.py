import numpy as np
import pandas as pd

np.random.seed(42)

NUM_WALLETS = 1000

data = {
    "tx_10m": np.random.poisson(2, NUM_WALLETS),
    "tx_1h": np.random.poisson(8, NUM_WALLETS),
    "unique_contracts_24h": np.random.poisson(4, NUM_WALLETS),
    "access_requests_10m": np.random.poisson(1, NUM_WALLETS),
    "failed_requests_1h": np.random.poisson(0.2, NUM_WALLETS),
    "new_contract_ratio": np.random.beta(2, 8, NUM_WALLETS),
    "avg_transfer_value": np.random.lognormal(2, 0.5, NUM_WALLETS),
    "flagged_counterparties": np.random.binomial(1, 0.02, NUM_WALLETS),
}

df = pd.DataFrame(data)

df.to_csv("normal_wallets.csv", index=False)

print("Generated normal_wallets.csv")
print(df.head())