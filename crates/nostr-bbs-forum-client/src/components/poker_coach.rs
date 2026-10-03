//! The practice table's Coach box: asks the coach agent about each decision
//! the member faces and shows its reply.
//!
//! On every move into "your turn" (held for [`coach::DEBOUNCE_MS`]) the box
//! DMs the coach a prompt built from the member's own seat view
//! ([`coach::build_prompt`]) through the DM store, then watches the store for
//! the reply ([`coach::Ledger`]). A reply to a decision already taken is
//! dropped. The box never blocks the game: the action buttons know nothing
//! of it.

use leptos::prelude::*;

use crate::auth::use_auth;
use crate::dm::use_dm_store;
use crate::poker::coach::{self, Ledger};
use crate::poker::{HandState, Legal, SeatView};
use crate::relay::{ConnectionState, RelayConnection};
use crate::utils::set_timeout_once;

/// What the box is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CoachState {
    /// Nothing asked yet, or the decision asked about has passed.
    Idle,
    /// A request is out.
    Waiting,
    /// The coach's advice for the decision in front of the member.
    Reply(String),
    /// No reply within [`coach::REPLY_TIMEOUT_MS`].
    TimedOut,
    /// The request could not be sent.
    Failed(String),
}

fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// The Coach box. Mount it under the practice table only, and only where the
/// operator names a coach and the member's `poker_coach` preference is on.
#[component]
pub fn PokerCoach(
    /// The coach agent's pubkey (64 lowercase hex).
    coach: String,
    /// The practice hand, as the engine keeps it (its log and seed).
    hand: RwSignal<Option<HandState>>,
    /// The member's view of the hand.
    #[prop(into)]
    seat_view: Signal<Option<SeatView>>,
    /// The legal envelope of the seat to act.
    #[prop(into)]
    legal: Signal<Option<Legal>>,
) -> impl IntoView {
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let relay_authed = relay.authenticated();
    let dm = use_dm_store();

    let state = RwSignal::new(CoachState::Idle);
    let ledger = StoredValue::new(Ledger::default());
    let request_seq = StoredValue::new(0u64);
    let current_request = StoredValue::new(0u64);

    // The decision in front of the member, when it is their turn.
    let decision = Memo::new(move |_| {
        let v = seat_view.get()?;
        let l = legal.get()?;
        hand.with(|h| {
            let h = h.as_ref()?;
            coach::decision_key(&v, &l, &h.hand.seed_hex, h.hand.log.len())
        })
    });

    // Replies arrive as DMs: listen once the relay session is authenticated
    // (kind-1059 REQs are AUTH-gated).
    let subscribed = StoredValue::new(false);
    let relay_sub = relay.clone();
    Effect::new(move |_| {
        if conn_state.get() != ConnectionState::Connected || !relay_authed.get() {
            return;
        }
        if subscribed.get_value() {
            return;
        }
        let (Some(signer), Some(me)) = (auth.get_signer(), auth.pubkey().get_untracked()) else {
            return;
        };
        subscribed.set_value(true);
        dm.subscribe_incoming(&relay_sub, signer, &me);
    });
    let relay_cleanup = relay.clone();
    on_cleanup(move || dm.cleanup(&relay_cleanup));

    let coach_pk = StoredValue::new(coach);
    let relay_send = StoredValue::new(relay);
    let ask = move |key: String| {
        let prompt = seat_view
            .get_untracked()
            .zip(legal.get_untracked())
            .and_then(|(v, l)| {
                hand.with_untracked(|h| {
                    let h = h.as_ref()?;
                    coach::build_prompt(&v, &l, &h.hand.log, h.hand.limit_cap)
                })
            });
        let Some(prompt) = prompt else {
            return;
        };
        if conn_state.get_untracked() != ConnectionState::Connected || !relay_authed.get_untracked()
        {
            state.set(CoachState::Failed(
                "Not connected to the relay yet, so the coach could not be asked.".into(),
            ));
            return;
        }
        let (Some(signer), Some(me)) = (auth.get_signer(), auth.pubkey().get_untracked()) else {
            state.set(CoachState::Failed(
                "Your session has no signing key; sign in again to ask the coach.".into(),
            ));
            return;
        };
        let id = request_seq.get_value() + 1;
        request_seq.set_value(id);
        current_request.set_value(id);
        let to = coach_pk.get_value();
        if let Err(e) = relay_send.with_value(|r| dm.send_message(r, &to, &prompt, signer, &me)) {
            state.set(CoachState::Failed(e));
            return;
        }
        ledger.update_value(|l| l.sent(id, key, now_secs()));
        state.set(CoachState::Waiting);
        set_timeout_once(
            move || {
                if current_request.try_get_value() == Some(id)
                    && state.try_get_untracked() == Some(CoachState::Waiting)
                {
                    state.set(CoachState::TimedOut);
                }
            },
            coach::REPLY_TIMEOUT_MS,
        );
    };

    // Ask on every move into a new decision, once it has held for the
    // debounce. A wait for a decision that has passed ends quietly.
    Effect::new(move |_| {
        let current = decision.get();
        if state.get_untracked() == CoachState::Waiting {
            state.set(CoachState::Idle);
        }
        let Some(key) = current else {
            return;
        };
        set_timeout_once(
            move || {
                if decision.try_get_untracked().flatten().as_deref() == Some(key.as_str()) {
                    ask(key);
                }
            },
            coach::DEBOUNCE_MS,
        );
    });

    // Pair each new message from the coach with the request it answers; show
    // it only while that request's decision is still the member's.
    let replies = dm.received_from(coach_pk.get_value());
    Effect::new(move |_| {
        let messages = replies.get();
        let coach = coach_pk.get_value();
        let mut answered = Vec::new();
        ledger.update_value(|l| answered = l.absorb(&coach, &messages, now_secs()));
        if let Some(text) = coach::reply_for_current(
            &answered,
            current_request.get_value(),
            decision.get_untracked().as_deref(),
        ) {
            state.set(CoachState::Reply(text));
        }
    });

    // A send that fails after the optimistic hand-off surfaces in the store.
    let store_error = dm.error();
    Effect::new(move |_| {
        if let Some(e) = store_error.get() {
            if state.get_untracked() == CoachState::Waiting {
                state.set(CoachState::Failed(e));
            }
        }
    });

    let body = move || {
        match state.get() {
        CoachState::Idle => view! {
            <p class="text-sm text-gray-400">"Coach is ready"</p>
        }
        .into_any(),
        CoachState::Waiting => view! {
            <p class="text-sm text-gray-300 flex items-center gap-2">
                <span
                    class="animate-spin inline-block w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full"
                    aria-hidden="true"
                ></span>
                "Asking JunkieJarvis…"
            </p>
        }
        .into_any(),
        CoachState::Reply(text) => view! {
            <p class="text-sm text-gray-100 whitespace-pre-wrap break-words">{text}</p>
        }
        .into_any(),
        CoachState::TimedOut => view! {
            <p class="text-sm text-gray-400">"No reply from the coach this time"</p>
        }
        .into_any(),
        CoachState::Failed(e) => view! {
            <p class="text-sm text-red-400">{e}</p>
        }
        .into_any(),
    }
    };

    view! {
        <section class="glass-card p-4 space-y-2" aria-live="polite" aria-label="Coach">
            <h2 class="text-sm font-semibold text-white">"Coach"</h2>
            {body}
        </section>
    }
}
