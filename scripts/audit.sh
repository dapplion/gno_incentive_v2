#!/bin/bash
set -e

cd "$(dirname "$0")"
cd audit
npm install
node fetch_registered_users.js
node fetch_deposit_events.js
node map_user_status.js
node withdrawable_balance.js
# Read-only report of which Safes are eligible for removeFunderOwner.
# Sends NO transactions; pass --execute (with PRIVATE_KEY) to act on it.
node remove_expired_funder_owners.js
