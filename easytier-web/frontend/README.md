# EasyTier Web frontend

The management console uses Vue 3, PrimeVue 4 and Tailwind 3. Device
configuration and runtime views reuse `easytier-frontend-lib`.

## Development

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm --dir easytier-web/frontend dev
```

The development proxy defaults to `http://localhost:11211`. Set
`API_BASE_URL` to use another backend. Production API discovery and hash
routes remain compatible with existing deployments.

`src/theme.ts` contains the Web-specific Aura preset; `src/console.css`
contains the console layout and shared-component compatibility tokens.
Register the Web PrimeVue configuration first, then register the shared
library with `skipPrimeVue: true` to preserve the console preset. These
styles are not imported by the GUI or config generator.

## Verification

```sh
pnpm --dir easytier-web/frontend exec playwright install chromium
pnpm --dir easytier-web/frontend test:browser
pnpm --dir easytier-web/frontend-lib test:config-ui
pnpm --dir easytier-web/frontend-lib test:network-config
```

The browser command builds the application, starts a local preview on
port 5198, and uses intercepted API responses. It covers summary refresh
and recovery, search and sorting, device deep links and drawer history,
network creation, gateway discovery, unsaved settings, secret regeneration,
member changes and deletion confirmation. No real controller is modified.

The layout checks cover English and Chinese, light and dark themes, and
1440px, 1024px and 390px viewports. To save screenshots outside the repo:

```sh
WEB_SCREENSHOT_DIR=/tmp/easytier-web-redesign \
  pnpm --dir easytier-web/frontend test:browser
```

Set `WEB_TEST_URL` to test an already running frontend instead of starting
the preview server. Browser checks exercise simulated device responses;
they do not replace integration testing against a live EasyTier network.

### End-to-end test

The end-to-end test needs the `rust` Docker container with access to the
repository and its shared `target` directory. Build the Core binary inside
the container so it can run there, then restore the build directory's owner
for the host-side Web build:

```sh
docker exec rust bash -lc "cd \"$PWD\" && cargo build -p easytier --bin easytier-core"
sudo chown -R "$(id -u):$(id -g)" target
pnpm --dir easytier-web/frontend test:e2e
```

This test uses a fresh SQLite database, a real Web server, a Chromium browser,
and a Core process with a TUN device. It checks network creation, member
configuration, ACL persistence, live peer and route RPCs, and offline member
deletion across Web and Core restarts. It does not intercept API requests.
