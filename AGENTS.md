# Repository Guidelines

## Project Structure & Module Organization

EasyTier is a Rust workspace with several user interfaces. `easytier-core/` contains networking primitives, while `easytier/` provides the CLI and primary runtime. Protocol definitions and generated bindings live in `easytier-proto/`. Web packages are under `easytier-web/` (`frontend`, `frontend-lib`, and `config-generator`); the Vue/Tauri desktop and mobile client is in `easytier-gui/`. Platform integrations and smaller utilities belong in `easytier-contrib/`, `easytier-go/`, `easytier-js/`, and `tauri-plugin-vpnservice/`. Shared documentation, images, and automation are in `docs/`, `assets/`, `script/`, and `.github/workflows/`.

## Build, Test, and Development Commands

- `pnpm -r install`: install all JavaScript workspace dependencies (Node 21+ and pnpm 9+).
- `cargo build`: build the default Rust workspace members; use `cargo build --release` for optimized binaries.
- `cargo test --no-default-features --features=full --verbose`: run the main Rust test suite used by contributors.
- `cargo fmt --all -- --check`: verify Rust formatting.
- `cargo clippy --all-targets --features full --all -- -D warnings`: run the CI lint gate.
- `pnpm --dir easytier-web/frontend-lib dev`: run the shared web UI locally.
- `pnpm --dir easytier-web/frontend-lib test`: run its Vitest and network-config checks.
- `pnpm --dir easytier-gui dev`: build the frontend library and launch the GUI web shell.
- `pnpm --dir easytier-gui lint`: lint GUI TypeScript and Vue files.

## Coding Style & Naming Conventions

Use `rustfmt` defaults and keep Clippy warning-free. Rust modules, functions, and tests use `snake_case`; types and traits use `PascalCase`. Vue and TypeScript use two-space indentation, `camelCase` identifiers, and `PascalCase.vue` component names. Follow nearby code for imports and semicolon style. Do not manually edit generated protobuf or auto-import files; update their source or generator instead.

## Testing Guidelines

Add focused tests beside Rust modules or under a crate's `tests/` directory. Frontend tests use Vitest and follow `*.spec.ts` or `*.test.ts`; shared UI tests belong in `easytier-web/frontend-lib/tests/`. Run the narrowest relevant suite during development, then the applicable workspace checks before submission. Tests should be isolated and repeatable; preserve existing coverage for changed behavior.

## Commit & Pull Request Guidelines

Use Conventional Commits, usually with a scope: `feat(gui): add peer details`, `fix(dns): handle CNAME chains`, or `docs: update setup`. Keep commits focused. Open PRs against `develop`, explain the purpose and behavior change, link related issues, and list validation performed. Include screenshots or recordings for visible UI changes and update documentation when commands, configuration, or user-facing behavior changes.
