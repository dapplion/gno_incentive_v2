import fs from "fs";
import path from "path";
import pLimit from "p-limit";

/* ─────────────── configuration ─────────────────────────────────────────── */
const DEPOSITS_CSV   = path.resolve("deposit_events.csv");     // DepositEvent rows
const USERS_CSV      = path.resolve("registered_users.csv");   // RegisteredUser rows
const OUT_CSV        = path.resolve("withdrawal_status.csv");

const RPC_GBC        = "https://rpc-gbc.gnosischain.com";
const CONC_LIMIT     = 5;                       // parallel validator RPCs

const SLOTS_PER_EPOCH = 16;
const SECS_PER_SLOT   = 5;
const FAR_FUTURE_EPOCH = 18_446_744_073_709_551n;          // 2^64-1

/* ─────────────── helpers ───────────────────────────────────────────────── */
const wcForSafe = safe =>
  "0x01" + "0".repeat(22) + safe.toLowerCase().replace(/^0x/, "");

const splitCSV = txt => txt.trim().split(/\r?\n/).slice(1);    // drop header

function loadWithdrawalMap() {
  const map = {};
  for (const line of splitCSV(fs.readFileSync(DEPOSITS_CSV, "utf8"))) {
    if (!line) continue;
    const [, , pubkey, wc] = line.split(",");
    (map[wc.toLowerCase()] ??= []).push(pubkey);
  }
  return map;
}

function loadUserMap(wcMap) {
  // { beneficiary -> { safe, pubkeys[] } }
  const res = {}; 
  for (const line of splitCSV(fs.readFileSync(USERS_CSV, "utf8"))) {
    if (!line) continue;
    const [, event, beneficiary, safe] = line.split(",");
    if (event !== "RegisteredUser") continue;

    const wc   = wcForSafe(safe);
    const pubs = wcMap[wc.toLowerCase()];
    if (pubs?.length) {
      res[beneficiary.toLowerCase()] = {
        safe: safe.toLowerCase(),
        pubkeys: pubs
      };
    }
  }
  return res;
}

async function genesisTime() {
  const r = await fetch(`${RPC_GBC}/eth/v1/beacon/genesis`);
  if (!r.ok) throw new Error(`genesis: ${r.status} ${r.statusText}`);
  return Number((await r.json()).data.genesis_time);
}

async function validatorInfo(pubkey) {
  const url = `${RPC_GBC}/eth/v1/beacon/states/head/validators/${pubkey}`;
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    const d = (await r.json()).data.validator;
    return {
      index: d.index,
      status: d.status,
      withdrawable_epoch: BigInt(d.withdrawable_epoch)
    };
  } catch (e) {
    return { index: "", status: `error:${e.message}`, withdrawable_epoch: 0n };
  }
}

function epochToDate(genesis, epoch) {
  if (!epoch || epoch >= FAR_FUTURE_EPOCH) return "not withdrawn";
  const secs = genesis + Number(epoch) * SLOTS_PER_EPOCH * SECS_PER_SLOT;
  return "withdrawn at " + new Date(secs * 1e3).toISOString();
}

/* ─────────────── main ──────────────────────────────────────────────────── */
(async () => {
  console.log("Loading CSV files …");
  const wcMap   = loadWithdrawalMap();
  const userMap = loadUserMap(wcMap);
  const genesis = await genesisTime();
  console.log("Genesis UTC:", new Date(genesis * 1e3).toISOString());

  const limit   = pLimit(CONC_LIMIT);
  const pending = [];                              // promises for all look-ups
  const grouped = {};                              // { beneficiary -> rows[] }

  for (const [user, info] of Object.entries(userMap)) {
    const { safe, pubkeys } = info;
    for (const pk of pubkeys) {
      pending.push(limit(async () => {
        const { withdrawable_epoch } = await validatorInfo(pk);
        const date = epochToDate(genesis, withdrawable_epoch);
        const row = [
          user,
          safe,
          pk,
          date
        ];
        (grouped[user] ??= []).push(row);
      }));
    }
  }

  await Promise.all(pending);

  /* -------- write grouped CSV ------------------------------------------- */
  const header = "beneficiary,safe,pubkey,withdrawable_date\n";
  const body   = Object.values(grouped)
                       .flatMap(rows => rows)
                       .map(cols => cols.join(","))
                       .join("\n") + "\n";
  console.log(body);

  fs.writeFileSync(OUT_CSV, header + body);
  console.log(`✔ ${OUT_CSV} written with rows grouped by beneficiary`);
})();

