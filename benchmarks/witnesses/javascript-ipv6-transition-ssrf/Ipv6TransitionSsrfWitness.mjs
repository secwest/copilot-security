import assert from "node:assert/strict";
import { isIP } from "node:net";
import test from "node:test";

function isPrivateIpv4(host) {
  return /^(?:10\.|127\.|169\.254\.|192\.168\.)/.test(host);
}

function embeddedIpv4(firstWord, secondWord) {
  const value =
    (Number.parseInt(firstWord, 16) << 16) | Number.parseInt(secondWord, 16);
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join(".");
}

function canonicalizeTransitionLiteral(host) {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized.startsWith("::ffff:")) return normalized.slice(7);
  if (normalized.startsWith("64:ff9b::")) {
    const words = normalized.slice(9).split(":");
    return embeddedIpv4(words.at(-2), words.at(-1));
  }
  if (normalized.startsWith("2002:")) {
    const words = normalized.split(":");
    return embeddedIpv4(words[1], words[2]);
  }
  return normalized;
}

const transitionLiterals = [
  "::ffff:127.0.0.1",
  "64:ff9b::7f00:1",
  "2002:7f00:1::",
];

test("IPv4-only guard accepts every modeled transition encoding", () => {
  for (const literal of transitionLiterals) {
    assert.equal(isIP(literal), 6);
    assert.equal(isPrivateIpv4(literal), false);
  }
});

test("complete canonicalization exposes the embedded private address", () => {
  for (const literal of transitionLiterals) {
    assert.equal(isPrivateIpv4(canonicalizeTransitionLiteral(literal)), true);
  }
});
