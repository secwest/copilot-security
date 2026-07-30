import { describe, expect, test } from "bun:test";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
} from "../src/scan-comparison.js";

function finding(occurrenceId: string): ScanComparisonInput["before"][number] {
  return { occurrenceId };
}

function fakeCopilot(response: unknown) {
  let prompt = "";
  const copilot: NonNullable<ScanComparisonOptions["copilot"]> = {
    startThread() {
      return {
        async run(value) {
          prompt = value;
          return { finalResponse: JSON.stringify(response) };
        },
      };
    },
  };
  return { copilot, prompt: () => prompt };
}

describe("semantic scan comparison", () => {
  test("matches findings through the Copilot adapter", async () => {
    const fake = fakeCopilot({
      matches: [
        {
          beforeOccurrenceIds: ["before-1"],
          afterOccurrenceIds: ["after-1"],
          confidence: "high",
          reason: "same vulnerable data flow",
        },
      ],
      uncertain: [],
    });

    const result = await matchScanFindings(
      {
        before: [finding("before-1")],
        after: [finding("after-1")],
      },
      { copilot: fake.copilot },
    );
    expect(result.matches).toHaveLength(1);
    expect(fake.prompt()).toContain("before-1");
    expect(fake.prompt()).toContain("after-1");
  });

  test("rejects identifiers that were not supplied", async () => {
    const fake = fakeCopilot({
      matches: [
        {
          beforeOccurrenceIds: ["invented"],
          afterOccurrenceIds: ["after-1"],
          confidence: "high",
          reason: "invalid",
        },
      ],
      uncertain: [],
    });
    await expect(
      matchScanFindings(
        {
          before: [finding("before-1")],
          after: [finding("after-1")],
        },
        { copilot: fake.copilot },
      ),
    ).rejects.toThrow("unknown");
  });
});
