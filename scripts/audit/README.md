# Audit & maintenance scripts

Off-chain helpers to monitor the DAppNode GNO incentive program and run its
end-of-program maintenance. All scripts read addresses/RPCs from env with
mainnet defaults baked in.

## Config (env)

| Var | Default | Used by |
|-----|---------|---------|
| `RPC_URL` | `https://rpc.gnosischain.com` | all EL reads |
| `RPC_GBC` | `https://rpc-gbc.gnosischain.com` | `map_user_status.js` (beacon API) |
| `DEPLOYER` | `0x485c6Be503D32511c1282b68dD99E85f250572c3` | `fetch_registered_users.js` |
| `DEPOSIT_CONTRACT` | `0x0B98057eA310F4d31F2a452B414647007d1645d9` | deposit/balance scripts |
| `MODULE` | `0x99f62576edf6B41A6F3C0ea6e5050a7e3F9407eb` | `remove_expired_funder_owners.js` |
| `PRIVATE_KEY` | — | only `remove_expired_funder_owners.js --execute` |

Run the full read-only audit with `../audit.sh` (installs deps, runs everything below
in order; the last step is a dry-run report and sends no transactions).

## Scripts

- **`fetch_registered_users.js`** — exports `RegisteredUser(beneficiary, safe)` events from
  the deployer → `registered_users.csv` (incremental/resumable).
- **`fetch_deposit_events.js`** — exports `DepositEvent` rows from the SBC deposit contract
  → `deposit_events.csv` (incremental/resumable).
- **`map_user_status.js`** — joins users↔deposits, queries the beacon node per validator,
  reports withdrawable/exit status → `withdrawal_status.csv`.
- **`withdrawable_balance.js`** — reads `withdrawableAmount(safe)` per Safe →
  `withdrawable_balances.csv`.
- **`remove_expired_funder_owners.js`** — for every registered Safe, calls
  `removeFunderOwner` once the program has expired (downgrades the 2/2 Safe to a 1/1
  owned solely by the beneficiary). See below.

## `remove_expired_funder_owners.js`

End-of-program maintenance: anyone may call `removeFunderOwner(safe)` on the SafeModule
after a Safe's `expiry`, which removes the funder as a Safe owner. This script enumerates
all registered Safes, classifies each, writes `funder_owner_status.csv`, and optionally
submits the calls.

Status classes:
- `ELIGIBLE` — expired, not terminated, funder still an owner → call would succeed.
- `already-removed` — funder is no longer an owner (already processed).
- `not-expired` — `block.timestamp < expiry`.
- `terminated` — funder retains control by design; skipped.

```bash
# Dry run: report only, sends NOTHING. Writes funder_owner_status.csv.
node remove_expired_funder_owners.js

# Execute: send removeFunderOwner for every ELIGIBLE Safe.
# Requires --execute AND PRIVATE_KEY. Each call is simulated first, so bad
# entries are skipped and re-running is idempotent.
PRIVATE_KEY=0x... node remove_expired_funder_owners.js --execute
```
