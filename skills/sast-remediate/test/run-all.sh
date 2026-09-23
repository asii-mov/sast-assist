#!/usr/bin/env sh
# Everything, one command. Run from the skill directory.
set -e
echo "== prose =="        && (cd ../.. && node tools/check-prose.cjs)
echo "\n== skill tree ==" && node tools/validate-skill.cjs
echo "\n== unit =="        && node test/selftest.cjs
echo "\n== agent =="      && node test/agent.test.cjs
echo "\n== partition ==" && node test/partition.test.cjs
echo "\n== pipeline ==="  && node test/run.test.cjs
echo "\n== end to end ==" && node test/e2e-witness.cjs
echo "\nall green"
