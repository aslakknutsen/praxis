// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Shane Utt

//! Tests for the router filter.

use std::collections::HashMap;

use http::{HeaderMap, HeaderValue};
use praxis_core::config::Route;

use super::{
    ResolvedRoute, RouterFilter,
    matching::{path_specificity, route_matches_request, should_stop_early, update_best_match},
};
use crate::{FilterAction, filter::HttpFilter};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn match_root() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "default".into(),
    }]);
    let route = router.match_route("/anything", None, &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "default", "root prefix should match any path");
}

#[test]
fn longest_prefix_wins() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
        Route {
            path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "api".into(),
        },
    ]);

    let route = router.match_route("/api/users", None, &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "api", "longer /api/ prefix should win");

    let route = router.match_route("/static/main.js", None, &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "default", "non-api path should fall back to root");
}

#[test]
fn host_filtering() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "api",
        "matching host should select host-specific route"
    );

    let route = router
        .match_route("/", Some("other.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching host should fall back to default"
    );
}

#[test]
fn host_with_port() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("api.example.com".into()),
        headers: None,
        cluster: "api".into(),
    }]);

    let route = router
        .match_route("/", Some("api.example.com:8080"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "api",
        "host with port should match after stripping port"
    );
}

#[test]
fn no_match() {
    let router = make_router(vec![Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    }]);
    assert!(
        router.match_route("/other", None, &HeaderMap::new(), None).is_none(),
        "non-matching prefix should return None"
    );
}

#[test]
fn no_match_wrong_host() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("api.example.com".into()),
        headers: None,
        cluster: "api".into(),
    }]);
    assert!(
        router.match_route("/", Some("other.com"), &HeaderMap::new(), None).is_none(),
        "wrong host should return no match"
    );
}

#[test]
fn from_config_parses_routes() {
    let yaml = serde_yaml::from_str::<serde_yaml::Value>(
        r#"
            routes:
              - path_prefix: "/api/"
                cluster: "api"
              - path_prefix: "/"
                cluster: "default"
            "#,
    )
    .unwrap();

    let filter = RouterFilter::from_config(&yaml).unwrap();

    assert_eq!(filter.name(), "router", "filter name should be router");
}

#[test]
fn from_config_empty_routes_key_missing() {
    let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());

    let filter = RouterFilter::from_config(&yaml).unwrap();

    assert_eq!(filter.name(), "router", "missing routes key should still create router");
}

#[tokio::test]
async fn on_request_sets_cluster_on_match() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "default".into(),
    }]);
    let req = crate::test_utils::make_request(http::Method::GET, "/");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "matched route should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("default"),
        "cluster should be set to matched route"
    );
}

#[tokio::test]
async fn on_request_rejects_on_no_match() {
    let router = make_router(vec![Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    }]);
    let req = crate::test_utils::make_request(http::Method::GET, "/other");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 404),
        "unmatched route should reject with 404"
    );
    assert!(ctx.cluster.is_none(), "cluster should remain unset on no match");
}

#[tokio::test]
async fn on_request_combined_host_and_path() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/v1/users");
    req.headers.insert("host", HeaderValue::from_static("api.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "host header should select api cluster"
    );

    let req2 = crate::test_utils::make_request(http::Method::GET, "/v1/users");
    let mut ctx2 = crate::test_utils::make_filter_context(&req2);
    drop(router.on_request(&mut ctx2).await.unwrap());
    assert_eq!(
        ctx2.cluster.as_deref(),
        Some("default"),
        "missing host should select default"
    );
}

#[test]
fn route_matches_by_header() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "matching header should select header-constrained route"
    );
}

#[test]
fn route_skips_mismatched_header() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
    assert!(
        router.match_route("/chat", None, &hdrs, None).is_none(),
        "mismatched header value should return no match"
    );
}

#[test]
fn route_with_headers_wins_over_plain() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
            cluster: "claude_sonnet".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "header-constrained route should win over plain"
    );
}

#[test]
fn route_without_headers_used_as_fallback() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
            cluster: "claude_sonnet".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-model", HeaderValue::from_static("mistral-small-latest"));
    let route = router.match_route("/chat", None, &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching header should fall back to default"
    );
}

#[tokio::test]
async fn host_falls_back_to_uri_authority() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "api".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let req = crate::context::Request {
        method: http::Method::GET,
        uri: "http://api.example.com/v1/data".parse().unwrap(),
        headers: HeaderMap::new(),
    };
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "URI authority should be used when Host header is absent"
    );
}

#[test]
fn multi_value_header_matches_any() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::from([("x-model".into(), "claude-sonnet-4-5".into())])),
        cluster: "claude_sonnet".into(),
    }]);

    let mut hdrs = HeaderMap::new();
    hdrs.append("x-model", HeaderValue::from_static("claude-3"));
    hdrs.append("x-model", HeaderValue::from_static("claude-sonnet-4-5"));
    let route = router.match_route("/chat", None, &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "claude_sonnet",
        "any matching value in multi-value header should match"
    );
}

#[test]
fn ipv6_host_with_port() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("[::1]".into()),
        headers: None,
        cluster: "ipv6".into(),
    }]);

    let route = router.match_route("/", Some("[::1]:8080"), &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 with port should match");
}

#[test]
fn ipv6_host_without_port() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("[::1]".into()),
        headers: None,
        cluster: "ipv6".into(),
    }]);

    let route = router.match_route("/", Some("[::1]"), &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "ipv6", "bracketed IPv6 without port should match");
}

#[test]
fn empty_route_table() {
    let router = make_router(vec![]);
    assert!(
        router.match_route("/anything", None, &HeaderMap::new(), None).is_none(),
        "empty route table should match nothing"
    );
}

#[test]
fn route_with_host_and_headers() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("api.example.com".into()),
            headers: Some(HashMap::from([("x-version".into(), "v2".into())])),
            cluster: "api-v2".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-version", HeaderValue::from_static("v2"));
    let route = router.match_route("/", Some("api.example.com"), &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "api-v2",
        "route with both host and headers should match"
    );
}

#[test]
fn same_prefix_same_constraints_first_wins() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: Some(HashMap::from([("x-a".into(), "1".into())])),
            cluster: "first".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: Some(HashMap::from([("x-b".into(), "2".into())])),
            cluster: "second".into(),
        },
    ]);

    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-a", HeaderValue::from_static("1"));
    hdrs.insert("x-b", HeaderValue::from_static("2"));
    let route = router.match_route("/", None, &hdrs, None).unwrap();
    assert_eq!(
        &*route.cluster, "first",
        "equal-constraint routes should prefer first match"
    );
}

#[test]
fn empty_headers_map_matches_everything() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::new()),
        cluster: "vacuous".into(),
    }]);

    let route = router.match_route("/test", None, &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "vacuous", "empty headers map should match everything");
}

#[tokio::test]
async fn on_request_strips_port_from_host_header() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "example".into(),
    }]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("host", HeaderValue::from_static("example.com:9090"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "host with port should still match route"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("example"),
        "port should be stripped from Host header for matching"
    );
}

#[test]
fn route_matches_request_path_only_hit() {
    let route = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    assert!(
        route_matches_request(&resolved, "/api/users", None, &HeaderMap::new(), None),
        "path-only route should match when prefix matches"
    );
}

#[test]
fn route_matches_request_path_miss() {
    let route = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/other", None, &HeaderMap::new(), None),
        "path-only route should not match when prefix differs"
    );
}

#[test]
fn route_matches_request_host_hit() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    assert!(
        route_matches_request(&resolved, "/", Some("example.com"), &HeaderMap::new(), None),
        "host-constrained route should match when host is equal"
    );
}

#[test]
fn route_matches_request_host_miss() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/", Some("other.com"), &HeaderMap::new(), None),
        "host-constrained route should not match when host differs"
    );
}

#[test]
fn route_matches_request_host_miss_when_no_host() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "ex".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    assert!(
        !route_matches_request(&resolved, "/", None, &HeaderMap::new(), None),
        "host-constrained route should not match when no host is provided"
    );
}

#[test]
fn route_matches_request_header_hit() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::from([("x-key".into(), "val".into())])),
        cluster: "h".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-key", HeaderValue::from_static("val"));
    assert!(
        route_matches_request(&resolved, "/", None, &hdrs, None),
        "header-constrained route should match when header is present"
    );
}

#[test]
fn route_matches_request_header_miss() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: Some(HashMap::from([("x-key".into(), "val".into())])),
        cluster: "h".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-key", HeaderValue::from_static("wrong"));
    assert!(
        !route_matches_request(&resolved, "/", None, &hdrs, None),
        "header-constrained route should not match when header value differs"
    );
}

#[test]
fn route_matches_request_compound() {
    let route = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: Some(HashMap::from([("x-ver".into(), "2".into())])),
        cluster: "c".into(),
    };
    let resolved = ResolvedRoute {
        route,
        wildcard_suffix: None,
    };
    let mut hdrs = HeaderMap::new();
    hdrs.insert("x-ver", HeaderValue::from_static("2"));
    assert!(
        route_matches_request(&resolved, "/api/data", Some("example.com"), &hdrs, None),
        "compound route should match when path, host, and header all match"
    );
    assert!(
        !route_matches_request(&resolved, "/api/data", Some("other.com"), &hdrs, None),
        "compound route should fail when host mismatches"
    );
    assert!(
        !route_matches_request(&resolved, "/other", Some("example.com"), &hdrs, None),
        "compound route should fail when path mismatches"
    );
}

#[test]
fn update_best_match_prefers_more_constraints_at_same_prefix() {
    let route_a = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "a".into(),
    };
    let route_b = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "b".into(),
    };
    let best = update_best_match(None, &route_a);
    let best = update_best_match(best, &route_b);
    assert_eq!(
        &*best.unwrap().2.cluster,
        "b",
        "route with more constraints should win at same prefix length"
    );
}

#[test]
fn update_best_match_prefers_longer_prefix() {
    let short = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "short".into(),
    };
    let long = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "long".into(),
    };
    let best = update_best_match(None, &short);
    let best = update_best_match(best, &long);
    assert_eq!(&*best.unwrap().2.cluster, "long", "route with longer prefix should win");
}

#[test]
fn update_best_match_keeps_current_when_dominated() {
    let first = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("example.com".into()),
        headers: None,
        cluster: "first".into(),
    };
    let second = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "second".into(),
    };
    let best = update_best_match(None, &first);
    let best = update_best_match(best, &second);
    assert_eq!(
        &*best.unwrap().2.cluster,
        "first",
        "dominated route should not replace current best"
    );
}

#[test]
fn should_stop_early_true_when_prefix_shorter_than_best() {
    let best_route = Route {
        path_prefix: "/api/v2/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "best".into(),
    };
    let shorter = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "shorter".into(),
    };
    let best = Some((path_specificity(&best_route), 0, &best_route));
    assert!(
        should_stop_early(best, &shorter),
        "should stop when current route prefix is shorter than best"
    );
}

#[test]
fn should_stop_early_false_when_prefix_equal_to_best() {
    let best_route = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "best".into(),
    };
    let same = Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "same".into(),
    };
    let best = Some((path_specificity(&best_route), 0, &best_route));
    assert!(
        !should_stop_early(best, &same),
        "should not stop when prefix lengths are equal"
    );
}

#[test]
fn should_stop_early_false_when_no_best() {
    let route = Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "any".into(),
    };
    assert!(
        !should_stop_early(None, &route),
        "should not stop when there is no current best"
    );
}

#[test]
fn path_prefix_without_trailing_slash_is_allowed() {
    let router = RouterFilter::new(vec![Route {
        path_prefix: "/api".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    }])
    .expect("Gateway-aligned prefix should not require trailing slash");
    let route = router.match_route("/api/users", None, &HeaderMap::new(), None).unwrap();
    assert_eq!(&*route.cluster, "api");
    assert!(
        router.match_route("/apikeys", None, &HeaderMap::new(), None).is_none(),
        "segment boundary: /api must not match /apikeys"
    );
}

#[test]
fn path_prefix_exact_segment_matches_without_extra_slash() {
    let router = make_router(vec![Route {
        path_prefix: "/test".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "t".into(),
    }]);
    for path in ["/test", "/test/", "/test/x"] {
        let route = router.match_route(path, None, &HeaderMap::new(), None).unwrap_or_else(|| {
            panic!("prefix /test should match path {path:?}");
        });
        assert_eq!(&*route.cluster, "t", "path {path:?}");
    }
    assert!(
        router.match_route("/testing", None, &HeaderMap::new(), None).is_none(),
        "/test must not match /testing"
    );
}

#[test]
fn wildcard_host_matches_subdomain() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.example.com".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "*.example.com should match api.example.com"
    );
}

#[test]
fn wildcard_host_does_not_match_bare_domain() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.example.com".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some("example.com"), &HeaderMap::new(), None)
            .is_none(),
        "*.example.com should not match bare example.com"
    );
}

#[test]
fn wildcard_host_does_not_match_multi_level_subdomain() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.example.com".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some("a.b.example.com"), &HeaderMap::new(), None)
            .is_none(),
        "*.example.com should not match multi-level subdomain a.b.example.com"
    );
}

#[test]
fn wildcard_host_with_port() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.example.com".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("www.example.com:8080"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard host should match after stripping port"
    );
}

#[test]
fn wildcard_host_case_insensitive() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.Example.COM".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    let route = router
        .match_route("/", Some("API.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard host matching should be case-insensitive"
    );
}

#[test]
fn wildcard_host_with_fallback() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "wildcard",
        "wildcard route should match api.example.com"
    );

    let route = router.match_route("/", Some("other.dev"), &HeaderMap::new(), None).unwrap();
    assert_eq!(
        &*route.cluster, "default",
        "non-matching host should fall back to default"
    );
}

#[test]
fn exact_host_wins_over_wildcard_same_constraints() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("api.example.com".into()),
            headers: None,
            cluster: "exact".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        },
    ]);

    let route = router
        .match_route("/", Some("api.example.com"), &HeaderMap::new(), None)
        .unwrap();
    assert_eq!(
        &*route.cluster, "exact",
        "exact host match should win over wildcard (first-match semantics)"
    );
}

#[test]
fn wildcard_host_does_not_match_empty_subdomain() {
    let router = make_router(vec![Route {
        path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: Some("*.example.com".into()),
        headers: None,
        cluster: "wildcard".into(),
    }]);

    assert!(
        router
            .match_route("/", Some(".example.com"), &HeaderMap::new(), None)
            .is_none(),
        "*.example.com should not match .example.com (empty subdomain)"
    );
}

#[tokio::test]
async fn on_request_wildcard_host_via_host_header() {
    let router = make_router(vec![
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: Some("*.example.com".into()),
            headers: None,
            cluster: "wildcard".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);

    let mut req = crate::test_utils::make_request(http::Method::GET, "/");
    req.headers.insert("host", HeaderValue::from_static("app.example.com"));
    let mut ctx = crate::test_utils::make_filter_context(&req);
    drop(router.on_request(&mut ctx).await.unwrap());
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("wildcard"),
        "wildcard should match via Host header"
    );
}

#[tokio::test]
async fn on_request_uses_original_path_when_rewritten_path_is_none() {
    let router = make_router(vec![
        Route {
            path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "api".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "original path match should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("api"),
        "should route based on original path when rewritten_path is None"
    );
}

#[tokio::test]
async fn on_request_uses_rewritten_path_when_set() {
    let router = make_router(vec![
        Route {
            path_prefix: "/internal/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "internal".into(),
        },
        Route {
            path_prefix: "/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
            host: None,
            headers: None,
            cluster: "default".into(),
        },
    ]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/v1/data");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.rewritten_path = Some("/internal/data".to_owned());
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Continue),
        "rewritten path match should continue"
    );
    assert_eq!(
        ctx.cluster.as_deref(),
        Some("internal"),
        "should route based on rewritten_path, not original"
    );
}

#[tokio::test]
async fn on_request_rewritten_path_no_match_still_rejects() {
    let router = make_router(vec![Route {
        path_prefix: "/api/".into(),
        path_exact: None,
        path_regex: None,
        methods: None,
        host: None,
        headers: None,
        cluster: "api".into(),
    }]);
    let req = crate::test_utils::make_request(http::Method::GET, "/api/users");
    let mut ctx = crate::test_utils::make_filter_context(&req);
    ctx.rewritten_path = Some("/unknown/path".to_owned());
    let action = router.on_request(&mut ctx).await.unwrap();
    assert!(
        matches!(action, FilterAction::Reject(r) if r.status == 404),
        "rewritten path that matches no route should reject with 404"
    );
    assert!(
        ctx.cluster.is_none(),
        "cluster should remain unset when rewritten path matches nothing"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn make_router(routes: Vec<Route>) -> RouterFilter {
    RouterFilter::new(routes).expect("test routes should be valid")
}
