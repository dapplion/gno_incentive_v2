// fetch-withdrawable.js   – Node 18+, reads registered_users.csv
import fs from "fs";
import path from "path";
import { ethers } from "ethers";
import pLimit from "p-limit";

/* ——— files & RPC ———————————————————————————————————————————————— */
const USERS_CSV   = path.resolve("registered_users.csv");          // block_number,event,beneficiary,safe
const OUT_CSV     = path.resolve("withdrawable_balances.csv");

const RPC_URL     = "https://rpc.ankr.com/gnosis/" +          // put your key after the slash if needed
                    "a8516201036e8ef56434e5fe19d84b9004dd5b466ff0735c8aafe83e6f9bd250";
const CONTRACT    = "0x0B98057eA310F4d31F2a452B414647007d1645d9";
const ABI         = ["function withdrawableAmount(address) view returns (uint256)"];

const CONC_LIMIT  = 5;                                        // parallel reads

/* ——— 1. collect unique Safe addresses ————————————————————————— */
const safes = new Set(
  fs.readFileSync(USERS_CSV, "utf8")
    .trim()
    .split(/\r?\n/)
    .slice(1)                          // skip header
    .map(line => line.split(",")[3].toLowerCase())
);

/* ——— 2. prepare chain objects ———————————————————————————————— */
const provider = new ethers.JsonRpcProvider(RPC_URL);
const contract = new ethers.Contract(CONTRACT, ABI, provider);

/* ——— 3. query mapping with throttling ———————————————————————— */
const limit  = pLimit(CONC_LIMIT);
const tasks  = [];

for (const safe of safes) {
  tasks.push(limit(async () => {
    const wei = (await contract.withdrawableAmount(safe)).toString();
    const amount = ethers.formatEther(wei);
    return { safe, amount };
  }));
}

const results = await Promise.all(tasks);

/* ——— 4. write grouped CSV ———————————————————————————————— */
const header = "safe,withdrawable_amount_wei\n";
const body   = results
  .sort((a, b) => a.safe.localeCompare(b.safe))     // deterministic order
  .map(({ safe, amount }) => `${safe},${amount}`)
  .join("\n") + "\n";
console.log(body);

fs.writeFileSync(OUT_CSV, header + body);
console.log(`✔ ${OUT_CSV} written with ${results.length} rows`);

