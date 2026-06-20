//! Wiring between the proxy and the WASM plugin host.
//!
//! Builds one [`PluginChain`] per route (global plugins first, then the route's
//! own) at startup, and runs the request/response flow for a plugin-enabled
//! route: buffer the request, run the request plugins, forward to the upstream
//! over a buffered HTTP client, then run the response plugins.

use crate::upstream;
use std::path::Path;
use std::time::Duration;
use zaphyl_config::Config;
use zaphyl_core::router::Target;
use zaphyl_plugin::{ChainOutcome, Plugin, PluginChain, PluginHost, Request, Response};

/// A boxed, thread-safe error.
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// The proxy's plugin state: a chain per route plus the buffered fetch client.
pub struct Plugins {
    chains: Vec<PluginChain>,
    max_body: u64,
    read_timeout: Option<Duration>,
    fetch_client: upstream::FetchClient,
}

impl Plugins {
    /// Build the plugin chains from config, or `None` if no plugins are
    /// configured. Compiles every referenced `.wasm`.
    ///
    /// # Errors
    /// Fails if a plugin file is missing or is not a valid component.
    pub fn build(
        config: &Config,
        upstream_ca: Option<&Path>,
        read_timeout: Option<Duration>,
    ) -> Result<Option<Self>, DynError> {
        let has_global = config
            .plugins
            .as_ref()
            .is_some_and(|p| !p.global.is_empty());
        let has_route = config.routes.iter().any(|r| !r.plugins.is_empty());
        if !has_global && !has_route {
            return Ok(None);
        }

        let host = PluginHost::new()?;
        let global = match &config.plugins {
            Some(plugins) => load_all(&host, &plugins.global)?,
            None => Vec::new(),
        };
        let mut chains = Vec::with_capacity(config.routes.len());
        for route in &config.routes {
            let mut plugins = global.clone();
            plugins.extend(load_all(&host, &route.plugins)?);
            chains.push(PluginChain::new(host.clone(), plugins));
        }

        let max_body = config
            .plugins
            .as_ref()
            .map_or(1024 * 1024, |p| p.max_body_bytes);
        Ok(Some(Self {
            chains,
            max_body,
            read_timeout,
            fetch_client: upstream::build_fetch_client(upstream_ca),
        }))
    }

    /// The (non-empty) plugin chain for a route, or `None` if it has no plugins.
    #[must_use]
    pub fn chain(&self, route_id: usize) -> Option<&PluginChain> {
        self.chains.get(route_id).filter(|chain| !chain.is_empty())
    }

    /// Largest body buffered for a plugin (bigger requests bypass plugins).
    #[must_use]
    pub fn max_body(&self) -> u64 {
        self.max_body
    }

    /// Run the request plugins, forward to `target` if not short-circuited, then
    /// run the response plugins. Returns the response to send downstream.
    ///
    /// # Errors
    /// Fails if a plugin traps or the upstream cannot be reached.
    pub async fn run(
        &self,
        chain: &PluginChain,
        request: Request,
        host: &str,
        target: &Target,
    ) -> Result<Response, DynError> {
        let outcome = {
            let chain = chain.clone();
            tokio::task::spawn_blocking(move || chain.handle_request(request)).await??
        };
        let request = match outcome {
            ChainOutcome::Respond(response) => return Ok(response),
            ChainOutcome::Continue(request) => request,
        };

        let (status, headers, body) = upstream::fetch(
            &self.fetch_client,
            target,
            &request.method,
            &request.path,
            host,
            &request.headers,
            request.body,
            self.read_timeout,
            self.max_body,
        )
        .await?;

        let response = Response {
            status,
            headers,
            body,
        };
        let chain = chain.clone();
        Ok(tokio::task::spawn_blocking(move || chain.handle_response(response)).await??)
    }
}

/// Load every plugin path into a compiled [`Plugin`].
fn load_all(host: &PluginHost, paths: &[String]) -> Result<Vec<Plugin>, DynError> {
    paths
        .iter()
        .map(|path| host.load(path.clone(), Path::new(path)).map_err(Into::into))
        .collect()
}
