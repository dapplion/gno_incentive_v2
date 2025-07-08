// export-deposits.js  – fixed for big indices / amounts
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

// ---------------------------------------------------------------- config ----
const RPC_URL   = "https://rpc.ankr.com/gnosis/a8516201036e8ef56434e5fe19d84b9004dd5b466ff0735c8aafe83e6f9bd250";
const CONTRACT  = "0x0B98057eA310F4d31F2a452B414647007d1645d9";
const START     = 19_469_077;
const STEP      = 10_000;
const CSV_PATH  = path.resolve("deposit_events.csv");

// ----------------------------------------------- ABI + topic0 ---------------
const ABI = [
  "event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index)"
];
const iface         = new ethers.Interface(ABI);
const TOPIC_DEPOSIT = ethers.id("DepositEvent(bytes,bytes,bytes,bytes,bytes)");

// ------------------------------------------------ CSV helpers ---------------
function ensureHeader() {
  if (!fs.existsSync(CSV_PATH)) {
    fs.writeFileSync(
      CSV_PATH,
      "block_number,index,pubkey,withdrawal_credentials,amount,signature\n"
    );
  }
}
function lastProcessedBlock() {
  if (!fs.existsSync(CSV_PATH)) return null;
  const lines = fs.readFileSync(CSV_PATH, "utf8").trim().split("\n");
  if (lines.length <= 1) return null;
  return Number(lines.at(-1).split(",")[0]) || null;
}
function append(line) {
  fs.appendFileSync(CSV_PATH, line + "\n");
}

// ---------------------------------------------------------------- main ------
(async () => {
  ensureHeader();
  const resume = (lastProcessedBlock() ?? (START - 1)) + 1;

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const latest   = await provider.getBlockNumber();
  console.log(`Exporting DepositEvent from block ${resume} to ${latest}`);

  for (let from = resume; from <= latest; from += STEP) {
    const to = Math.min(from + STEP - 1, latest);
    console.log(`--- scanning ${from} → ${to}`);

    const logs = await provider.getLogs({
      address: CONTRACT,
      fromBlock: from,
      toBlock:   to,
      topics: [TOPIC_DEPOSIT]
    });

    logs
      .sort((a, b) =>
        a.blockNumber !== b.blockNumber
          ? a.blockNumber - b.blockNumber
          : a.transactionIndex - b.transactionIndex
      )
      .forEach(log => {
        const ev     = iface.parseLog(log);

        // bytes → bigint → string  (safe for any 64-bit value and beyond)
        const index  = ethers.toBigInt(ev.args.index).toString();
        const amount = ethers.toBigInt(ev.args.amount).toString();

        const row = [
          log.blockNumber,
          index,
          ev.args.pubkey,
          ev.args.withdrawal_credentials,
          amount,
          ev.args.signature
        ].join(",");

        append(row);
        console.log(row);
      });
  }

  console.log("\n✔ deposit_events.csv updated without overflow issues");
})().catch(err => {
  console.error("ERROR:", err);
  process.exitCode = 1;
});

