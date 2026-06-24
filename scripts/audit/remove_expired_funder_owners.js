// remove_expired_funder_owners.js — Node 18+
//
// For every registered Safe, call `removeFunderOwner(safe)` on the SafeModule once the
// incentive program has expired. This permissionlessly downgrades each 2/2 Safe to a 1/1
// owned solely by the beneficiary (it removes the funder owner), as designed in
// GnosisDAppNodeIncentiveV2SafeModule.removeFunderOwner.
//
// Safety model:
//   - Default mode is a DRY RUN: it only reads chain state, prints a report, and writes
//     funder_owner_status.csv. It sends NO transactions.
//   - To actually send transactions you must BOTH pass `--execute` AND set PRIVATE_KEY.
//   - Before sending, each call is simulated (staticCall + estimateGas). Safes whose call
//     would revert (not expired yet, terminated, funder already removed) are skipped, so
//     re-running is idempotent and never wastes gas.
//
// Inputs (env, all optional):
//   RPC_URL      Gnosis execution RPC          (default https://rpc.gnosischain.com)
//   MODULE       SafeModule address            (default mainnet deployment)
//   USERS_CSV    registered_users.csv path     (default ./registered_users.csv)
//   PRIVATE_KEY  sender key, required for --execute
//   CONFIRMATIONS  receipt confirmations to wait (default 1)
//
// Usage:
//   node remove_expired_funder_owners.js            # dry run / report
//   node remove_expired_funder_owners.js --execute  # send txs (needs PRIVATE_KEY)

import fs from "fs";
import path from "path";
import { ethers } from "ethers";
import pLimit from "p-limit";

/* ───────────────────────────── config ──────────────────────────────────── */
const RPC_URL   = process.env.RPC_URL || "https://rpc.gnosischain.com";
const MODULE    = process.env.MODULE  || "0x99f62576edf6B41A6F3C0ea6e5050a7e3F9407eb";
const USERS_CSV = path.resolve(process.env.USERS_CSV || "registered_users.csv");
const OUT_CSV   = path.resolve("funder_owner_status.csv");
const EXECUTE   = process.argv.includes("--execute");
const PRIVATE_KEY   = process.env.PRIVATE_KEY;
const CONFIRMATIONS = Number(process.env.CONFIRMATIONS ?? 1);
const CONC_LIMIT    = 5; // parallel read calls

/* ───────────────────────────── ABIs ────────────────────────────────────── */
const MODULE_ABI = [
  // public mapping getter: userInfos(Safe) -> struct fields
  "function userInfos(address) view returns (uint256 expiry, uint256 withdrawThreshold, address beneficiary, address funder, bool autoClaimEnabled, bool terminated)",
  "function removeFunderOwner(address from) external",
];
const SAFE_ABI = ["function isOwner(address owner) view returns (bool)"];

/* ───────────────────────────── helpers ─────────────────────────────────── */
function loadSafes() {
  if (!fs.existsSync(USERS_CSV)) {
    throw new Error(`${USERS_CSV} not found — run fetch_registered_users.js first`);
  }
  const seen = new Set();
  const rows = [];
  for (const line of fs.readFileSync(USERS_CSV, "utf8").trim().split(/\r?\n/).slice(1)) {
    if (!line) continue;
    const [, event, beneficiary, safe] = line.split(",");
    if (event !== "RegisteredUser") continue;
    const key = safe.toLowerCase();
    if (seen.has(key)) continue; // a beneficiary can only register one Safe, but be defensive
    seen.add(key);
    rows.push({ beneficiary, safe });
  }
  return rows;
}

const fmtTs = ts => (ts ? new Date(ts * 1000).toISOString() : "");

/* ───────────────────────────── main ────────────────────────────────────── */
(async () => {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const module   = new ethers.Contract(MODULE, MODULE_ABI, provider);

  const now    = Number((await provider.getBlock("latest")).timestamp);
  const safes  = loadSafes();
  console.log(`SafeModule: ${MODULE}`);
  console.log(`Chain time: ${fmtTs(now)} (${now})`);
  console.log(`Registered Safes: ${safes.length}\n`);

  const limit = pLimit(CONC_LIMIT);
  const records = await Promise.all(
    safes.map(({ beneficiary, safe }) =>
      limit(async () => {
        try {
          const info = await module.userInfos(safe);
          const expiry     = Number(info.expiry);
          const funder     = info.funder;
          const terminated = info.terminated;
          if (expiry === 0) {
            return { safe, beneficiary, expiry, funder, terminated, funderIsOwner: false, status: "not-registered" };
          }
          const safeC = new ethers.Contract(safe, SAFE_ABI, provider);
          const funderIsOwner = await safeC.isOwner(funder);

          let status;
          if (terminated)            status = "terminated";          // funder retains control by design
          else if (now < expiry)     status = "not-expired";
          else if (!funderIsOwner)   status = "already-removed";     // call would revert in Safe.removeOwner
          else                       status = "ELIGIBLE";
          return { safe, beneficiary, expiry, funder, terminated, funderIsOwner, status };
        } catch (e) {
          return { safe, beneficiary, expiry: 0, funder: "", terminated: false, funderIsOwner: false, status: `error:${e.shortMessage || e.message}` };
        }
      })
    )
  );

  /* -------- report -------- */
  const byStatus = {};
  for (const r of records) (byStatus[r.status] ??= []).push(r);

  const header = "safe,beneficiary,funder,expiry,expiry_iso,terminated,funder_is_owner,status\n";
  const body = records
    .sort((a, b) => a.expiry - b.expiry)
    .map(r => [r.safe, r.beneficiary, r.funder, r.expiry, fmtTs(r.expiry), r.terminated, r.funderIsOwner, r.status].join(","))
    .join("\n");
  fs.writeFileSync(OUT_CSV, header + body + "\n");

  console.log("Status summary:");
  for (const [s, rs] of Object.entries(byStatus).sort()) console.log(`  ${s.padEnd(16)} ${rs.length}`);
  console.log(`\n✔ ${OUT_CSV} written`);

  const eligible = byStatus["ELIGIBLE"] ?? [];
  if (eligible.length === 0) {
    console.log("\nNothing eligible to process.");
    return;
  }
  console.log(`\n${eligible.length} Safe(s) eligible for removeFunderOwner:`);
  for (const r of eligible) console.log(`  ${r.safe}  (expired ${fmtTs(r.expiry)})`);

  if (!EXECUTE) {
    console.log("\nDRY RUN — no transactions sent. Re-run with --execute and PRIVATE_KEY set to submit.");
    return;
  }
  if (!PRIVATE_KEY) {
    console.error("\n--execute given but PRIVATE_KEY is not set. Aborting.");
    process.exitCode = 1;
    return;
  }

  /* -------- execute -------- */
  const wallet  = new ethers.Wallet(PRIVATE_KEY, provider);
  const moduleW = module.connect(wallet);
  console.log(`\nSender: ${wallet.address}`);
  console.log(`Confirmations per tx: ${CONFIRMATIONS}\n`);

  let nonce = await provider.getTransactionCount(wallet.address, "pending");
  for (const r of eligible) {
    try {
      // Simulate first so a single bad entry never blocks the batch and we never pay for a revert.
      await moduleW.removeFunderOwner.staticCall(r.safe);
      const gas = await moduleW.removeFunderOwner.estimateGas(r.safe);
      const tx  = await moduleW.removeFunderOwner(r.safe, { nonce, gasLimit: (gas * 12n) / 10n });
      console.log(`  ${r.safe} → ${tx.hash} (nonce ${nonce})`);
      await tx.wait(CONFIRMATIONS);
      nonce += 1;
    } catch (e) {
      console.error(`  ${r.safe} SKIPPED: ${e.shortMessage || e.message}`);
    }
  }
  console.log("\n✔ Done.");
})().catch(err => {
  console.error("ERROR:", err);
  process.exitCode = 1;
});
