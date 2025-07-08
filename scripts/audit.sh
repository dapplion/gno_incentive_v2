#!/bin/bash
set -e

cd "$(dirname "$0")"
cd audit
npm install
node fetch_registered_users.js
node fetch_deposit_events.js
node map_user_status.js
node withdrawable_balance.js
