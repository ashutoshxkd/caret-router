//! The canary: a real question to every Codex seat on a fixed beat.
//!
//! The check endpoint and the maintenance sweep ask a seat for one token
//! of "hi", which proves the credential and not much else. A seat can pass
//! that and still stall, truncate or refuse a real turn. The canary asks
//! each Codex seat a question that needs a detailed answer — picked at
//! random from [`QUESTIONS`] — and keeps what it learned: whether the seat
//! answered, how long the headers and the whole answer took, and how long
//! the answer was.
//!
//! Three rules keep it from becoming the problem it is watching for:
//!
//! - **One question per seat at a time.** A seat still answering when the
//!   next tick arrives is skipped for that tick, so a slow seat is not
//!   stacked with more work than it already has.
//! - **Benched seats are left alone.** A seat the provider has benched on
//!   a quota window is recorded as `benched` and not asked until the
//!   window rolls: asking would only collect a `429` and spend nothing
//!   useful.
//! - **Starts are spread across the interval.** A hundred seats asked in
//!   the same millisecond is a burst the provider sees as one client.
//!
//! Each answer goes through [`crate::proxy::ask_key`], the check's own
//! path, so it settles the breaker and the seat's recorded state exactly
//! as a check does. It is off unless an interval is given.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use router_core::clock;
use router_core::config::ProviderKind;
use router_core::router::{CheckOutcome, ProviderRuntime};
use serde::Serialize;
use serde_json::{Value, json};

use crate::AppState;

/// The questions, one per line; `#` lines and blank lines are skipped.
pub const QUESTIONS: &str = include_str!("canary_questions.txt");

/// How many recent latencies a seat keeps for its percentiles.
const LATENCY_WINDOW: usize = 50;

/// How much of an answer is kept for the operator to read.
const ANSWER_PREVIEW_CHARS: usize = 400;

/// The questions, parsed.
pub fn questions() -> Vec<&'static str> {
    QUESTIONS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// One question put to one seat.
#[derive(Debug, Clone, Serialize)]
pub struct CanaryResult {
    pub model: Option<String>,
    pub question_id: usize,
    pub question: String,
    /// `ok`, `benched`, or the check's own word for a failure.
    pub status: String,
    pub detail: String,
    pub http_status: Option<u16>,
    pub headers_ms: Option<u64>,
    pub total_ms: u64,
    pub answer_chars: usize,
    pub output_tokens: Option<u64>,
    pub answer_preview: String,
    pub observed_ms: u64,
}

#[derive(Default)]
struct SeatStats {
    asked: u64,
    ok: u64,
    failed: u64,
    benched: u64,
    /// Total time of recent successful answers, newest last.
    latencies_ms: VecDeque<u64>,
    last: Option<CanaryResult>,
}

impl SeatStats {
    fn record(&mut self, result: CanaryResult) {
        match result.status.as_str() {
            "benched" => self.benched += 1,
            "ok" => {
                self.asked += 1;
                self.ok += 1;
                self.latencies_ms.push_back(result.total_ms);
                if self.latencies_ms.len() > LATENCY_WINDOW {
                    self.latencies_ms.pop_front();
                }
            }
            _ => {
                self.asked += 1;
                self.failed += 1;
            }
        }
        self.last = Some(result);
    }

    fn percentile(&self, pct: usize) -> Option<u64> {
        if self.latencies_ms.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = self.latencies_ms.iter().copied().collect();
        sorted.sort_unstable();
        let index = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
        sorted.get(index).copied()
    }
}

/// Which seats are mid-question, and what every seat has told us.
#[derive(Default)]
pub struct CanaryRegistry {
    in_flight: Mutex<HashSet<(String, String)>>,
    seats: Mutex<HashMap<(String, String), SeatStats>>,
    /// Set once the loop starts, so the report can say whether it is on.
    interval: Mutex<Option<Duration>>,
}

impl CanaryRegistry {
    /// Claim a seat for one question. `false` while it is still answering
    /// the last one.
    fn claim(&self, seat: &(String, String)) -> bool {
        self.in_flight
            .lock()
            .expect("canary mutex")
            .insert(seat.clone())
    }

    fn release(&self, seat: &(String, String)) {
        self.in_flight.lock().expect("canary mutex").remove(seat);
    }

    fn record(&self, seat: (String, String), result: CanaryResult) {
        self.seats
            .lock()
            .expect("canary mutex")
            .entry(seat)
            .or_default()
            .record(result);
    }

    /// Everything the canary knows, for the admin API.
    pub fn report(&self) -> Value {
        let interval = *self.interval.lock().expect("canary mutex");
        let in_flight = self.in_flight.lock().expect("canary mutex").clone();
        let seats = self.seats.lock().expect("canary mutex");
        let mut rows: Vec<Value> = seats
            .iter()
            .map(|((provider, key), stats)| {
                let success_rate = if stats.asked == 0 {
                    None
                } else {
                    Some(stats.ok as f64 / stats.asked as f64)
                };
                json!({
                    "provider": provider,
                    "key": key,
                    "asked": stats.asked,
                    "ok": stats.ok,
                    "failed": stats.failed,
                    "benched": stats.benched,
                    "success_rate": success_rate,
                    "p50_ms": stats.percentile(50),
                    "p95_ms": stats.percentile(95),
                    "in_flight": in_flight.contains(&(provider.clone(), key.clone())),
                    "last": stats.last,
                })
            })
            .collect();
        rows.sort_by(|a, b| {
            (a["provider"].as_str(), a["key"].as_str())
                .cmp(&(b["provider"].as_str(), b["key"].as_str()))
        });
        let asked: u64 = seats.values().map(|s| s.asked).sum();
        let ok: u64 = seats.values().map(|s| s.ok).sum();
        json!({
            "enabled": interval.is_some(),
            "interval_secs": interval.map(|d| d.as_secs_f64()),
            "questions": questions().len(),
            "seats": rows.len(),
            "asked": asked,
            "ok": ok,
            "failed": asked - ok,
            "results": rows,
        })
    }
}

/// Start the canary. Every `interval`, each Codex seat that is not still
/// answering is asked one question.
pub fn spawn(state: Arc<AppState>, interval: Duration) {
    let pool = questions();
    if pool.is_empty() {
        tracing::warn!("canary has no questions; not starting");
        return;
    }
    *state.canary.interval.lock().expect("canary mutex") = Some(interval);
    tracing::info!(
        interval_secs = interval.as_secs_f64(),
        questions = pool.len(),
        "canary started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let table = state.table.load();
            // Collected first so the routing snapshot is not held across
            // an await; a reload may swap it underneath us.
            let seats: Vec<(Arc<ProviderRuntime>, usize)> = table
                .providers()
                .filter(|p| p.kind == ProviderKind::CodexSubscription)
                .flat_map(|p| (0..p.keys.len()).map(|index| (p.clone(), index)))
                .collect();
            drop(table);

            let count = seats.len().max(1) as u32;
            for (slot, (provider, index)) in seats.into_iter().enumerate() {
                let seat = (provider.name.clone(), provider.keys[index].name.clone());
                if !state.canary.claim(&seat) {
                    continue;
                }
                let question_id = fastrand::usize(..pool.len());
                let question = pool[question_id];
                let delay = interval * slot as u32 / count;
                let state = state.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let result = ask(&state, &provider, index, question_id, question).await;
                    report_metrics(&seat, &result);
                    state.canary.release(&seat);
                    state.canary.record(seat, result);
                });
            }
        }
    });
}

/// Put one question to one seat.
async fn ask(
    state: &AppState,
    provider: &Arc<ProviderRuntime>,
    index: usize,
    question_id: usize,
    question: &str,
) -> CanaryResult {
    let key = &provider.keys[index];
    let base = CanaryResult {
        model: None,
        question_id,
        question: question.to_owned(),
        status: String::new(),
        detail: String::new(),
        http_status: None,
        headers_ms: None,
        total_ms: 0,
        answer_chars: 0,
        output_tokens: None,
        answer_preview: String::new(),
        observed_ms: clock::now_ms(),
    };

    let now = clock::now_ms();
    if key.breaker.is_benched(now) {
        return CanaryResult {
            status: "benched".into(),
            detail: key
                .breaker
                .benched_until_ms()
                .map(|until| format!("benched until {until} (unix ms)"))
                .unwrap_or_default(),
            ..base
        };
    }

    let candidates = crate::admin::probe_models(provider, &key.name);
    if candidates.is_empty() {
        let result = CanaryResult {
            status: "unknown".into(),
            detail: "no model declared for this credential".into(),
            ..base
        };
        key.record_check(CheckOutcome {
            status: result.status.clone(),
            detail: result.detail.clone(),
            http_status: None,
            probed: true,
            observed_ms: clock::now_ms(),
        });
        return result;
    }

    // Like the check: a model the plan no longer serves is refused with a
    // 400 that says nothing about the seat, so move on to the next one.
    let mut last = None;
    for model in candidates {
        let outcome =
            crate::proxy::ask_key(state, provider.clone(), &key.name, &model, question, None).await;
        let rejected_model = outcome.status == "rejected";
        last = Some((model, outcome));
        if !rejected_model {
            break;
        }
    }
    let (model, outcome) = last.expect("at least one candidate");
    let answer = outcome.answer.unwrap_or_default();
    // A 200 with nothing in it is not an answer, whatever the status said.
    let (status, detail) = if outcome.status == "ok" && answer.trim().is_empty() {
        (
            "empty_answer".to_owned(),
            "the seat answered with no text".to_owned(),
        )
    } else {
        (outcome.status, outcome.detail)
    };
    CanaryResult {
        model: Some(model),
        status,
        detail,
        http_status: outcome.http_status,
        headers_ms: outcome.headers_ms,
        total_ms: outcome.total_ms,
        answer_chars: answer.chars().count(),
        output_tokens: outcome.output_tokens,
        answer_preview: answer.chars().take(ANSWER_PREVIEW_CHARS).collect(),
        observed_ms: clock::now_ms(),
        ..base
    }
}

fn report_metrics(seat: &(String, String), result: &CanaryResult) {
    let (provider, key) = seat;
    metrics::counter!(
        "rapid_canary_total",
        "provider" => provider.clone(),
        "key" => key.clone(),
        "status" => result.status.clone(),
    )
    .increment(1);
    if result.status == "ok" {
        metrics::histogram!(
            "rapid_canary_duration_seconds",
            "provider" => provider.clone(),
            "key" => key.clone(),
        )
        .record(result.total_ms as f64 / 1000.0);
    }
    if result.status == "benched" {
        tracing::debug!(provider, key, "canary skipped a benched seat");
    } else {
        tracing::info!(
            provider,
            key,
            status = %result.status,
            question_id = result.question_id,
            headers_ms = result.headers_ms,
            total_ms = result.total_ms,
            answer_chars = result.answer_chars,
            output_tokens = result.output_tokens,
            detail = %result.detail,
            "canary answer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_are_a_hundred_questions() {
        assert_eq!(questions().len(), 100);
    }

    #[test]
    fn a_seat_is_asked_one_question_at_a_time() {
        let registry = CanaryRegistry::default();
        let seat = ("codex".to_owned(), "seat-1".to_owned());
        assert!(registry.claim(&seat));
        assert!(!registry.claim(&seat), "a seat mid-answer is skipped");
        registry.release(&seat);
        assert!(registry.claim(&seat));
    }

    fn result(status: &str, total_ms: u64) -> CanaryResult {
        CanaryResult {
            model: None,
            question_id: 0,
            question: String::new(),
            status: status.into(),
            detail: String::new(),
            http_status: None,
            headers_ms: None,
            total_ms,
            answer_chars: 0,
            output_tokens: None,
            answer_preview: String::new(),
            observed_ms: 0,
        }
    }

    #[test]
    fn benched_seats_do_not_count_against_success_rate() {
        let registry = CanaryRegistry::default();
        let seat = ("codex".to_owned(), "seat-1".to_owned());
        registry.record(seat.clone(), result("ok", 1000));
        registry.record(seat.clone(), result("ok", 3000));
        registry.record(seat.clone(), result("rate_limited", 50));
        registry.record(seat.clone(), result("benched", 0));
        let report = registry.report();
        let row = &report["results"][0];
        assert_eq!(row["asked"], 3);
        assert_eq!(row["ok"], 2);
        assert_eq!(row["failed"], 1);
        assert_eq!(row["benched"], 1);
        assert_eq!(row["p50_ms"], 1000);
        assert_eq!(row["p95_ms"], 3000);
        assert_eq!(row["last"]["status"], "benched");
    }
}
