# Repository Guidelines

## Project Structure & Module Organization
- `easytier/`: Rust core crate (bins: `easytier-core`, `easytier-cli`). Most unit/integration tests live under `easytier/src/**`.
- `easytier-web/`: Rust web components and frontend libs; see `frontend/` and `frontend-lib/` (managed via pnpm workspace).
- `easytier-gui/`: Desktop GUI (Vue 3 + Vite + Tauri).
- `easytier-contrib/`: Extensions (e.g., FFI, uptime, Android JNI).
- `tauri-plugin-vpnservice/`: Tauri plugin API used by the GUI.
- `assets/`, `script/`, `.github/`: static assets, helper scripts, CI.

## Build, Test, and Development Commands
- Build core fast: `cargo build -p easytier --release`
- Build web crate: `cargo build -p easytier-web --release`
- Run core locally: `cargo run --bin easytier-core -- -h`
- Workspace build (default members): `cargo build --workspace`
- GUI dev server: `cd easytier-gui && pnpm dev`
- GUI build: `cd easytier-gui && pnpm build && pnpm tauri build`
- Frontend libs: `pnpm -r install && pnpm -r build`
- Tests (Rust): `cargo test --no-default-features --features=full --verbose`

## Coding Style & Naming Conventions
- Rust: 4-space indent; `snake_case` for functions/modules, `PascalCase` for types. Run `cargo fmt --all` and `cargo clippy --workspace --all-features -D warnings` before pushing.
- TypeScript/Vue: follow ESLint config in `easytier-gui` (`pnpm lint`, `pnpm lint:fix`). Prefer `kebab-case` file names and `PascalCase` Vue components.
- Commit messages: Conventional Commits (e.g., `feat:`, `fix:`, `docs:`).

## Testing Guidelines
- Framework: Rust `cargo test` across crates; tests live next to code (`#[cfg(test)] mod tests`) and under `easytier/src/tests/`.
- Write unit tests for new logic and update affected integration tests. Keep tests deterministic and isolated.
- Linux networking tests may require capabilities/modules; see `CONTRIBUTING.md` for platform specifics.

## Commit & Pull Request Guidelines
- Branch from `develop`: `git checkout -b feature/<short-scope>`.
- PRs target `develop`; include: purpose, linked issues, CLI/GUI screenshots for UI changes, and notable trade-offs.
- CI must pass; run format/lint/tests locally first.

## Security & Configuration Tips
- Do not commit secrets or tokens. Use env vars or local config.
- When testing networking features, avoid exposing non-test ports on public hosts.

## Agent-Specific Instructions
- Apply minimal, focused patches; do not refactor unrelated areas.
- Respect workspace layout and existing tooling; prefer `cargo`, `pnpm`, and Tauri commands above.
