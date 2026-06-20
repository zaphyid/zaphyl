//! A sample Zaphyl plugin used by `zaphyl-plugin`'s tests: it blocks `/blocked`
//! and tags every response with `X-Plugin: ran`.
#[allow(warnings)]
mod bindings;

use bindings::exports::zaphyl::proxy::filter::{Guest, HttpRequest, HttpResponse, RequestAction};

struct Component;

impl Guest for Component {
    fn handle_request(req: HttpRequest) -> RequestAction {
        // A runaway path used to test the host's execution deadline.
        if req.path == "/loop" {
            let mut n: u64 = 0;
            loop {
                n = core::hint::black_box(n.wrapping_add(1));
            }
        }
        if req.path == "/blocked" {
            RequestAction::Respond(HttpResponse {
                status: 403,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: b"blocked by plugin".to_vec(),
            })
        } else {
            RequestAction::Continue(req)
        }
    }

    fn handle_response(mut resp: HttpResponse) -> HttpResponse {
        resp.headers
            .push(("x-plugin".to_string(), "ran".to_string()));
        resp
    }
}

bindings::export!(Component with_types_in bindings);
