import { describe, expect, it } from "vitest";

import { encodeRuntimeConfig } from "../src/config";

describe("encodeRuntimeConfig", () => {
  it("encodes only capabilities supported by the browser profile", () => {
    const encoded = encodeRuntimeConfig({
      profile: "browser",
      instanceId: "019f94c2-8a97-7be3-b7a5-d6cea838c5d4",
      instanceName: "browser",
      networkName: "office",
      networkSecret: "secret",
      encryption: true,
      ipv4: "10.144.0.10/24",
      peers: ["wss://relay.example.com/"],
    });

    expect(encoded).toContain('ipv4 = "10.144.0.10/24"');
    expect(encoded).toContain('uri = "wss://relay.example.com/"');
    expect(encoded).toContain("use_smoltcp = true");
    expect(encoded).not.toContain("proxy_forward_by_system");
  });

  it("encodes an inbound-only Cloudflare relay", () => {
    const encoded = encodeRuntimeConfig({
      profile: "cloudflare",
      instanceId: "019f94c2-8a97-7be3-b7a5-d6cea838c5d4",
      instanceName: "relay",
      networkName: "office",
      networkSecret: "secret",
      encryption: false,
    });

    expect(encoded).toContain("proxy_forward_by_system = true");
    expect(encoded).toContain("enable_encryption = false");
    expect(encoded).not.toContain("[[peer]]");
    expect(encoded).not.toContain("use_smoltcp");
  });

  it("rejects unsupported Browser and Cloudflare capabilities", () => {
    expect(() =>
      encodeRuntimeConfig({
        profile: "browser",
        instanceId: "id",
        instanceName: "browser",
        networkName: "office",
        networkSecret: "secret",
        encryption: true,
        ipv4: "not-a-prefix",
        peers: [],
      }),
    ).toThrow("ipv4 must be an IPv4 address with a network prefix");

    expect(() =>
      encodeRuntimeConfig({
        profile: "cloudflare",
        instanceId: "id",
        instanceName: "relay",
        networkName: "office",
        networkSecret: "secret",
        encryption: true,
        peers: ["wss://relay.example.com/"],
      }),
    ).toThrow("Cloudflare relay configuration cannot dial peers");
  });
});
