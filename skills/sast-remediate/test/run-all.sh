#!/usr/bin/env sh
# Everything, one command. Run from the skill directory.
set -e
echo "== prose =="        && (cd ../.. && node tools/check-prose.cjs)
echo "\n== skill tree ==" && node tools/validate-skill.cjs
echo "\n== schema types ==" && node tools/gen-schema-types.ts --check
echo "\n== types ==" && { [ -x ../../node_modules/.bin/tsc ] || { echo "run npm install at the repository root first"; exit 1; }; } && (cd ../.. && node_modules/.bin/tsc -p tsconfig.json) && echo "tsc: no errors"
echo "\n== unit =="        && node test/selftest.ts
echo "\n== agent =="      && node test/agent.test.ts
echo "\n== pipeline ==="  && node test/run.test.ts
echo "\n== pipeline (real git) ==" && node test/pipeline.real.test.ts
echo "\n== end to end ==" && node test/e2e-witness.ts
echo "\nall green"
