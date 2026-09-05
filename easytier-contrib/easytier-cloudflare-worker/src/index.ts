import { DurableObject } from "cloudflare:workers";
import coreModule from "./generated/easytier_core.wasm";

import { EasyTierRuntime } from "./core-runtime";
import type { HostWebSocketMetadata } from "./websocket-host";

export class EasyTierCoreObject extends DurableObject<Env> {
  private readonly runtime: EasyTierRuntime;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.runtime = new EasyTierRuntime(
      coreModule,
      this.env.EASYTIER_CONFIG_SECRET ?? this.env.EASYTIER_CONFIG,
    );
  }

  async fetch(request: Request): Promise<Response> {
    const upgrade = request.headers.get("Upgrade");
    if (upgrade?.toLowerCase() !== "websocket") {
      if (new URL(request.url).pathname !== "/health") {
        return new Response("Not found", { status: 404 });
      }
      try {
        return Response.json(await this.runtime.health());
      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: String(error),
          },
          { status: 503 },
        );
      }
    }
    if (!this.runtime.host.canAccept()) {
      return new Response("WebSocket connection limit reached", {
        status: 503,
      });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.binaryType = "arraybuffer";
    const handle = this.runtime.host.register(server);
    server.addEventListener("message", (event) => {
      this.runtime.host.receive(handle, event.data);
    });
    server.addEventListener("close", () => {
      this.runtime.host.remoteClose(handle);
    });
    server.addEventListener("error", () => {
      this.runtime.host.remoteError(handle);
    });
    server.accept();

    try {
      await this.runtime.attachWebSocket(
        handle,
        this.metadataFor(request, handle),
      );
    } catch (error) {
      this.runtime.host.reject(handle);
      console.error(
        JSON.stringify({
          event: "easytier_websocket_attach_failed",
          error: String(error),
        }),
      );
      return new Response("EasyTier core unavailable", { status: 503 });
    }

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  private metadataFor(
    request: Request,
    handle: bigint,
  ): HostWebSocketMetadata {
    const local = new URL(request.url);
    local.protocol = local.protocol === "https:" ? "wss:" : "ws:";
    const remote = new URL(`wss://client.invalid/${handle}`);
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
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === "/runtime-capabilities") {
      return Response.json({
        jspi:
          typeof WebAssembly.Suspending === "function" &&
          typeof WebAssembly.promising === "function",
      });
    }
    return env.EASYTIER_CORE.getByName(env.EASYTIER_OBJECT_NAME).fetch(
      request,
    );
  },
} satisfies ExportedHandler<Env>;
