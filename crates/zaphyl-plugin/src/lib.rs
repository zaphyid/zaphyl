//! WebAssembly plugin host for Zaphyl.
//!
//! Wraps Wasmtime's component model so the proxy can run sandboxed plugins that
//! filter requests and responses. All Wasmtime details live here; the proxy
//! depends only on this crate's API ([`PluginHost`], [`Plugin`], [`Request`],
//! [`Response`], [`Action`]).
//!
//! Plugins run in a fresh store per call with a minimal WASI context that grants
//! no filesystem, network, environment, or clock access - they are pure compute
//! over the request/response they are handed.

use std::path::Path;
use std::time::Duration;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p2::add_to_linker_sync;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// How often the engine epoch is bumped; with [`EXECUTION_DEADLINE_TICKS`] this
/// caps a single plugin call's run time.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// A plugin call may run for at most this many epoch ticks (~1 second).
const EXECUTION_DEADLINE_TICKS: u64 = 100;
/// Maximum linear memory a plugin instance may allocate (64 MiB).
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// The generated host bindings for the `zaphyl:proxy/filter` WIT world.
#[allow(missing_docs)]
mod bindings {
    wasmtime::component::bindgen!({
        world: "plugin",
        path: "wit",
    });
}

use bindings::exports::zaphyl::proxy::filter as wit;

/// An HTTP request handed to a plugin.
#[derive(Debug, Clone)]
pub struct Request {
    /// Request method.
    pub method: String,
    /// Request path and query.
    pub path: String,
    /// Request headers (order preserved, duplicates allowed).
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
    /// Client IP address.
    pub client_ip: String,
}

/// An HTTP response produced or modified by a plugin.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

/// A plugin's decision about a request.
#[derive(Debug, Clone)]
pub enum Action {
    /// Continue to the next plugin / the upstream with this (possibly modified)
    /// request.
    Continue(Request),
    /// Short-circuit with this response, without contacting the upstream.
    Respond(Response),
}

/// The per-call store state: a sandboxed WASI context.
struct State {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl State {
    /// A WASI context with no host capabilities and a bounded memory budget.
    fn sandboxed() -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(MAX_MEMORY_BYTES)
                .build(),
        }
    }
}

/// Compiles and runs Zaphyl WebAssembly plugins.
#[derive(Clone)]
pub struct PluginHost {
    engine: Engine,
    linker: Linker<State>,
}

impl PluginHost {
    /// Create a host with the component model enabled and WASI linked in.
    ///
    /// # Errors
    /// Fails if the Wasmtime engine or linker cannot be set up.
    pub fn new() -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;

        // Bump the epoch on a background thread so a runaway plugin is
        // interrupted at its deadline instead of hanging the request.
        let ticker = engine.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(EPOCH_TICK);
                ticker.increment_epoch();
            }
        });

        let mut linker = Linker::new(&engine);
        add_to_linker_sync(&mut linker)?;
        Ok(Self { engine, linker })
    }

    /// Compile a plugin component from a `.wasm` file.
    ///
    /// # Errors
    /// Fails if the file cannot be read or is not a valid component.
    pub fn load(&self, name: impl Into<String>, path: &Path) -> anyhow::Result<Plugin> {
        let component = Component::from_file(&self.engine, path)?;
        Ok(Plugin {
            name: name.into(),
            component,
        })
    }
}

/// A compiled plugin ready to be invoked.
#[derive(Clone)]
pub struct Plugin {
    name: String,
    component: Component,
}

impl Plugin {
    /// The plugin's display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Run the plugin's `handle-request` hook in a fresh sandboxed store.
    ///
    /// # Errors
    /// Fails if the plugin cannot be instantiated or traps.
    pub fn handle_request(&self, host: &PluginHost, request: Request) -> anyhow::Result<Action> {
        let mut store = new_store(host);
        let bindings = bindings::Plugin::instantiate(&mut store, &self.component, &host.linker)?;
        let action = bindings
            .zaphyl_proxy_filter()
            .call_handle_request(&mut store, &to_wit_request(request))?;
        Ok(from_wit_action(action))
    }

    /// Run the plugin's `handle-response` hook in a fresh sandboxed store.
    ///
    /// # Errors
    /// Fails if the plugin cannot be instantiated or traps.
    pub fn handle_response(
        &self,
        host: &PluginHost,
        response: Response,
    ) -> anyhow::Result<Response> {
        let mut store = new_store(host);
        let bindings = bindings::Plugin::instantiate(&mut store, &self.component, &host.linker)?;
        let result = bindings
            .zaphyl_proxy_filter()
            .call_handle_response(&mut store, &to_wit_response(response))?;
        Ok(from_wit_response(result))
    }
}

/// The result of running the request phase of a plugin chain.
#[derive(Debug, Clone)]
pub enum ChainOutcome {
    /// Every plugin continued; forward this (possibly modified) request upstream.
    Continue(Request),
    /// A plugin short-circuited with this response; do not contact the upstream.
    Respond(Response),
}

/// An ordered chain of plugins applied to a request (global first, then
/// per-route). Cheap to clone (shares the compiled components).
#[derive(Clone)]
pub struct PluginChain {
    host: PluginHost,
    plugins: Vec<Plugin>,
}

impl PluginChain {
    /// Build a chain from a host and an ordered list of plugins.
    #[must_use]
    pub fn new(host: PluginHost, plugins: Vec<Plugin>) -> Self {
        Self { host, plugins }
    }

    /// Whether the chain has no plugins (so the proxy can skip buffering).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Run each plugin's `handle-request` in order, threading the (possibly
    /// modified) request through. Stops at the first plugin that responds.
    ///
    /// # Errors
    /// Fails if any plugin traps or cannot be instantiated.
    pub fn handle_request(&self, mut request: Request) -> anyhow::Result<ChainOutcome> {
        for plugin in &self.plugins {
            match plugin.handle_request(&self.host, request)? {
                Action::Continue(modified) => request = modified,
                Action::Respond(response) => return Ok(ChainOutcome::Respond(response)),
            }
        }
        Ok(ChainOutcome::Continue(request))
    }

    /// Run each plugin's `handle-response` in reverse order (middleware nesting).
    ///
    /// # Errors
    /// Fails if any plugin traps or cannot be instantiated.
    pub fn handle_response(&self, mut response: Response) -> anyhow::Result<Response> {
        for plugin in self.plugins.iter().rev() {
            response = plugin.handle_response(&self.host, response)?;
        }
        Ok(response)
    }
}

/// A fresh sandboxed store with the execution deadline and memory limiter set.
fn new_store(host: &PluginHost) -> Store<State> {
    let mut store = Store::new(&host.engine, State::sandboxed());
    store.set_epoch_deadline(EXECUTION_DEADLINE_TICKS);
    store.limiter(|state| &mut state.limits);
    store
}

fn to_wit_request(request: Request) -> wit::HttpRequest {
    wit::HttpRequest {
        method: request.method,
        path: request.path,
        headers: request.headers,
        body: request.body,
        client_ip: request.client_ip,
    }
}

fn from_wit_request(request: wit::HttpRequest) -> Request {
    Request {
        method: request.method,
        path: request.path,
        headers: request.headers,
        body: request.body,
        client_ip: request.client_ip,
    }
}

fn to_wit_response(response: Response) -> wit::HttpResponse {
    wit::HttpResponse {
        status: response.status,
        headers: response.headers,
        body: response.body,
    }
}

fn from_wit_response(response: wit::HttpResponse) -> Response {
    Response {
        status: response.status,
        headers: response.headers,
        body: response.body,
    }
}

fn from_wit_action(action: wit::RequestAction) -> Action {
    match action {
        wit::RequestAction::Continue(request) => Action::Continue(from_wit_request(request)),
        wit::RequestAction::Respond(response) => Action::Respond(from_wit_response(response)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Plugin, PluginHost, Request, Response};
    use std::path::PathBuf;

    #[test]
    fn host_starts() {
        assert!(PluginHost::new().is_ok());
    }

    #[test]
    fn loading_a_missing_file_errors() {
        let host = PluginHost::new().unwrap();
        assert!(
            host.load("missing", std::path::Path::new("does-not-exist.wasm"))
                .is_err()
        );
    }

    /// Load the sample plugin built by cargo-component, or `None` if it has not
    /// been built (so the test gracefully skips on a cold checkout / CI step).
    fn sample_plugin() -> Option<(PluginHost, Plugin)> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-plugins/filter/target/wasm32-wasip1/release/zaphyl_test_filter.wasm");
        if !path.exists() {
            eprintln!("sample plugin .wasm not built; skipping (run cargo-component build)");
            return None;
        }
        let host = PluginHost::new().unwrap();
        let plugin = host.load("filter", &path).unwrap();
        Some((host, plugin))
    }

    fn request(path: &str) -> Request {
        Request {
            method: "GET".to_owned(),
            path: path.to_owned(),
            headers: vec![],
            body: vec![],
            client_ip: "127.0.0.1".to_owned(),
        }
    }

    #[test]
    fn plugin_short_circuits_blocked_path() {
        let Some((host, plugin)) = sample_plugin() else {
            return;
        };
        match plugin.handle_request(&host, request("/blocked")).unwrap() {
            Action::Respond(response) => assert_eq!(response.status, 403),
            other => panic!("expected a respond action, got {other:?}"),
        }
    }

    #[test]
    fn plugin_continues_other_paths() {
        let Some((host, plugin)) = sample_plugin() else {
            return;
        };
        assert!(matches!(
            plugin.handle_request(&host, request("/ok")).unwrap(),
            Action::Continue(_)
        ));
    }

    #[test]
    fn plugin_tags_the_response() {
        let Some((host, plugin)) = sample_plugin() else {
            return;
        };
        let response = plugin
            .handle_response(
                &host,
                Response {
                    status: 200,
                    headers: vec![],
                    body: vec![],
                },
            )
            .unwrap();
        assert!(
            response
                .headers
                .iter()
                .any(|(name, value)| name == "x-plugin" && value == "ran")
        );
    }

    #[test]
    fn runaway_plugin_is_interrupted() {
        let Some((host, plugin)) = sample_plugin() else {
            return;
        };
        let start = std::time::Instant::now();
        // The plugin loops forever; the epoch deadline must trap it.
        assert!(plugin.handle_request(&host, request("/loop")).is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "deadline should interrupt the plugin promptly"
        );
    }

    #[test]
    fn chain_short_circuits_and_runs_response_in_reverse() {
        use super::{ChainOutcome, PluginChain};
        let Some((host, plugin)) = sample_plugin() else {
            return;
        };
        // Two copies of the same plugin.
        let chain = PluginChain::new(host, vec![plugin.clone(), plugin]);

        // A blocked path short-circuits at the first plugin.
        assert!(matches!(
            chain.handle_request(request("/blocked")).unwrap(),
            ChainOutcome::Respond(_)
        ));
        // An allowed path passes through both.
        assert!(matches!(
            chain.handle_request(request("/ok")).unwrap(),
            ChainOutcome::Continue(_)
        ));
        // Both response hooks run, so the tag is added twice.
        let response = chain
            .handle_response(Response {
                status: 200,
                headers: vec![],
                body: vec![],
            })
            .unwrap();
        let tags = response
            .headers
            .iter()
            .filter(|(name, value)| name == "x-plugin" && value == "ran")
            .count();
        assert_eq!(tags, 2);
    }
}
