import assert from "node:assert/strict";
import test from "node:test";

import { buildFixtures } from "../src/fixtures.mjs";

test("fixture corpus covers every client-side circuit and pins signal counts", async () => {
  const fixtures = await buildFixtures();
  assert.deepEqual(Object.keys(fixtures), [
    "wallet_create",
    "deposit",
    "input",
    "spend",
    "merge_k2",
    "merge_k4",
  ]);
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(fixtures).map(([name, fixture]) => [
        name,
        fixture.expectedPublic.length,
      ]),
    ),
    {
      wallet_create: 1,
      deposit: 5,
      input: 4,
      spend: 8,
      merge_k2: 6,
      merge_k4: 8,
    },
  );
  assert.notEqual(
    fixtures.input.expectedPublic[1],
    fixtures.deposit.expectedPublic[0],
  );
});
