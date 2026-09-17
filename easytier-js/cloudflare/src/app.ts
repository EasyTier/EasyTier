import { DurableObject } from "cloudflare:workers";

import {
  createEasyTierRuntime,
  type HostTunnelMetadata,
  type RuntimeAdapter,
  type RuntimeWebSocket,
} from "@easytier/runtime/adapter";
import type {
  CloudflareEasyTierOptions,
  EasyTierCloudflareApplication,
} from "./types.js";

const INSTANCE_ID_STORAGE_KEY = "easytier.instance-id";

export function createCloudflareApplication<Env>(
  module: WebAssembly.Module,
  options: CloudflareEasyTierOptions<Env>,
): EasyTierCloudflareApplication<Env> {
  const EasyTierDurableObject = class extends DurableObject<Env> {
    private runtimePromise: Promise<RuntimeAdapter> | undefined;

    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const upgrade = request.headers.get("Upgrade");
      if (upgrade?.toLowerCase() !== "websocket") {
        if (url.pathname !== "/health") {
          return new Response("Not found", { status: 404 });
        }
        try {
          const status = await (await this.runtime()).status();
          return Response.json({ ok: true, ...status });
        } catch (error) {
          console.error(
            JSON.stringify({
              event: "easytier_cloudflare_health_failed",
              error: String(error),
            }),
          );
          return Response.json(
            { ok: false, state: "stopped", connections: 0 },
            { status: 503 },
          );
        }
      }

      let runtime: RuntimeAdapter;
      try {
        runtime = await this.runtime();
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "easytier_cloudflare_start_failed",
            error: String(error),
          }),
        );
        return new Response("EasyTier relay unavailable", { status: 503 });
      }
      if (!runtime.canAcceptWebSocket()) {
        return new Response("WebSocket connection limit reached", {
          status: 503,
        });
      }

      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      try {
        await runtime.acceptWebSocket(
          server as unknown as RuntimeWebSocket,
          tunnelMetadata(request),
        );
      } catch (error) {
        console.error(
          JSON.stringify({
            event: "easytier_cloudflare_admission_failed",
            error: String(error),
          }),
        );
        return new Response("EasyTier relay unavailable", { status: 503 });
      }

      return new Response(null, { status: 101, webSocket: client });
    }

    private runtime(): Promise<RuntimeAdapter> {
      this.runtimePromise ??= this.initializeRuntime();
      return this.runtimePromise;
    }

    private async initializeRuntime(): Promise<RuntimeAdapter> {
      const config = await options.config(this.env);
      let instanceId = await this.ctx.storage.get<string>(
        INSTANCE_ID_STORAGE_KEY,
      );
      if (instanceId === undefined) {
        instanceId = crypto.randomUUID();
        await this.ctx.storage.put(INSTANCE_ID_STORAGE_KEY, instanceId);
      }
      return createEasyTierRuntime({
        module,
        config: {
          profile: "cloudflare",
          instanceId,
          instanceName: config.instanceName ?? "easytier-cloudflare",
          networkName: config.networkName,
          networkSecret: config.networkSecret,
          encryption: config.encryption ?? true,
        },
      });
    }
  };

  return {
    DurableObject: EasyTierDurableObject,
    async fetch(request, env, _context): Promise<Response> {
      const objectName =
        typeof options.objectName === "function"
          ? options.objectName(request, env)
          : (options.objectName ?? "primary");
      if (objectName.trim() === "") {
        return new Response("EasyTier object name is empty", { status: 500 });
      }
      return options.namespace(env).getByName(objectName).fetch(request);
    },
  };
}

function tunnelMetadata(request: Request): HostTunnelMetadata {
  const local = new URL(request.url);
  local.protocol = local.protocol === "https:" ? "wss:" : "ws:";
  const remote = new URL(`wss://client.invalid/${crypto.randomUUID()}`);
  const connectingIp = request.headers.get("CF-Connecting-IP");
  if (connectingIp !== null) {
    remote.searchParams.set("ip", connectingIp);
  }
  return {
    version: 1,
    local_url: local.toString(),
    remote_url: remote.toString(),
  };
}
