// export-events.js
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

// ------------------------------------------------------------------ config ---
const RPC_URL     = "https://rpc.ankr.com/gnosis/a8516201036e8ef56434e5fe19d84b9004dd5b466ff0735c8aafe83e6f9bd250";
const CONTRACT    = "0x485c6Be503D32511c1282b68dD99E85f250572c3";
const START_BLOCK = 35_247_675;          // fallback when no cache
const BATCH_SIZE  = 10_000;
const CSV_FILE    = path.resolve("registered_users.csv");

// ------------------------------------------------------- ABI + topic hashes ---
const iface = new ethers.Interface([
  "event RegisteredUser(address beneficiary, address safe)",
]);

const TOPIC_REGISTERED = ethers.id("RegisteredUser(address,address)");

// ------------------------------------------------------------- CSV helpers ---
function ensureHeader() {
  if (!fs.existsSync(CSV_FILE)) {
    fs.writeFileSync(CSV_FILE, "block_number,event,beneficiary,safe\n");
  }
}

function lastBlockInFile() {
  if (!fs.existsSync(CSV_FILE)) return null;
  const data = fs.readFileSync(CSV_FILE, "utf8").trim().split("\n");
  if (data.length <= 1) return null;                  // only header present
  const lastLine = data[data.length - 1].split(",");
  return Number(lastLine[0]) || null;
}

function appendCsv(row) {
  fs.appendFileSync(CSV_FILE, row + "\n");
}

// ------------------------------------------------------------------ main ----
async function main() {
  ensureHeader();
  const resumeFrom = (lastBlockInFile() ?? (START_BLOCK - 1)) + 1;
  const provider   = new ethers.JsonRpcProvider(RPC_URL);
  const latest     = await provider.getBlockNumber();

  console.log(`Resuming at block ${resumeFrom}. Scanning → ${latest} in ${BATCH_SIZE}-block batches.\n`);

  for (let from = resumeFrom; from <= latest; from += BATCH_SIZE) {
    const to = Math.min(from + BATCH_SIZE - 1, latest);
    console.log(`--- fetching logs: blocks ${from} to ${to}`);

    const logs = await provider.getLogs({
      address: CONTRACT,
      fromBlock: from,
      toBlock:   to,
      topics: [[TOPIC_REGISTERED]]   // OR-filter on topic0
    });

    logs
      .sort((a, b) =>
        a.blockNumber !== b.blockNumber
          ? a.blockNumber - b.blockNumber
          : a.transactionIndex - b.transactionIndex
      )
      .forEach(log => {
        const ev = iface.parseLog(log);
        const { beneficiary, safe } = ev.args;
        const csvRow = `${log.blockNumber},${ev.name},${beneficiary},${safe}`;
        appendCsv(csvRow);
        console.log(csvRow);
      });
  }

  console.log("\n✔ Done. All results are in out.csv");
}

// ----------------------------- always flush CSV even on fatal error ----------
main().catch(err => {
  console.error("ERROR:", err);
  process.exitCode = 1;
});

