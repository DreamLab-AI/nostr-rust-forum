//! The grant sync's queue of gift wraps waiting to be unwrapped.
//!
//! Wraps arrive a page (up to a thousand) at a time, newest first, and each
//! costs one or two signer decrypts plus, for a grant, an admin check and
//! IndexedDB writes. The queue bounds how many run at once and decides the
//! order:
//!
//! - **Newest-queued first (LIFO).** A page is delivered newest to oldest, so
//!   its oldest wraps (where grants live) are opened first, and a later page
//!   (older wraps) is served before the rest of an earlier one. A live wrap
//!   arriving mid-backlog is opened next rather than behind thousands.
//! - **At most [`MAX_CONCURRENT_UNWRAPS`] at once**, and only one while a
//!   signer that can refuse (NIP-07) has not yet decrypted anything this
//!   sign-in, so a fresh origin raises one permission prompt, not four.
//! - **Slots belong to a generation.** [`WrapQueue::reset`] (an identity
//!   switch) starts a new one: jobs of the old sign-in that finish later
//!   release nothing, so they cannot under-count the new sign-in's slots.
//!   The store also releases a slot whose job has run too long
//!   (`UNWRAP_SLOT_TIMEOUT_MS`), so one hung fetch or prompt cannot hold it,
//!   except a refusable signer's single slot before its first success: that
//!   slot waits on a permission prompt, and releasing it would raise another.
//! - **Refused wraps are parked** ([`WrapQueue::park`]) until the signer has
//!   decrypted another wrap, then queued once more as
//!   [`Attempt::AfterSignerSuccess`] (see
//!   [`super::grant_backlog::unwrap_failure_outcome`]).
//!
//! Pure, so it unit-tests natively.

use super::grant_backlog::{Attempt, SignerKind};

/// How many gift wraps are unwrapped and processed at once once the signer
/// is known to work. Each wrap is one NIP-44 decrypt through the signer and,
/// for a grant, the sealer's admin check (a network fetch, cached per
/// sealer) and IndexedDB writes. Four overlaps that network and storage
/// latency, which is where a local key's time goes, while keeping a NIP-07
/// extension (which serves requests one by one) to a short queue of its own.
/// It also stays under the browser's six connections per host for the admin
/// checks.
pub const MAX_CONCURRENT_UNWRAPS: usize = 4;

/// A running job's claim on a slot, returned by [`WrapQueue::start_next`] and
/// given back to [`WrapQueue::release`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    generation: u64,
}

/// A job taken from the queue to run.
#[derive(Debug)]
pub struct Started<J> {
    /// The job.
    pub job: J,
    /// Its slot, to release when it finishes (or times out).
    pub slot: Slot,
    /// Which attempt this is.
    pub attempt: Attempt,
    /// The signer's success count when it started, for [`WrapQueue::park`].
    pub successes_at_start: u64,
}

#[derive(Debug)]
struct Queued<J> {
    job: J,
    attempt: Attempt,
}

#[derive(Debug)]
struct Parked<J> {
    job: J,
    successes_at_start: u64,
}

/// The queue; `J` is whatever the store needs to run one wrap.
#[derive(Debug)]
pub struct WrapQueue<J> {
    generation: u64,
    active: usize,
    stack: Vec<Queued<J>>,
    parked: Vec<Parked<J>>,
    successes: u64,
    signer: SignerKind,
}

impl<J> Default for WrapQueue<J> {
    fn default() -> Self {
        Self {
            generation: 0,
            active: 0,
            stack: Vec::new(),
            parked: Vec::new(),
            successes: 0,
            signer: SignerKind::Local,
        }
    }
}

impl<J> WrapQueue<J> {
    /// An empty queue for a local signer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the sign-in's signer kind (called when the grant sync starts).
    pub fn set_signer(&mut self, signer: SignerKind) {
        self.signer = signer;
    }

    /// The sign-in's signer kind.
    pub fn signer(&self) -> SignerKind {
        self.signer
    }

    /// How many jobs may run at once now.
    pub fn limit(&self) -> usize {
        match (self.signer, self.successes) {
            (SignerKind::CanRefuse, 0) => 1,
            _ => MAX_CONCURRENT_UNWRAPS,
        }
    }

    /// Queue a job delivered by a subscription.
    pub fn push(&mut self, job: J) {
        self.stack.push(Queued {
            job,
            attempt: Attempt::First,
        });
    }

    /// Take the next job to run, if a slot is free.
    pub fn start_next(&mut self) -> Option<Started<J>> {
        if self.active >= self.limit() {
            return None;
        }
        let Queued { job, attempt } = self.stack.pop()?;
        self.active += 1;
        Some(Started {
            job,
            slot: Slot {
                generation: self.generation,
            },
            attempt,
            successes_at_start: self.successes,
        })
    }

    /// Give a slot back. A slot of an earlier generation is ignored.
    pub fn release(&mut self, slot: Slot) {
        if slot.generation == self.generation {
            self.active = self.active.saturating_sub(1);
        }
    }

    /// The signer decrypted a wrap: refused wraps parked before this success
    /// are queued again, once. Returns how many were queued.
    pub fn signer_succeeded(&mut self) -> usize {
        self.successes += 1;
        let parked = std::mem::take(&mut self.parked);
        parked
            .into_iter()
            .map(|p| usize::from(self.requeue_or_park(p)))
            .sum()
    }

    /// Hold a job whose first attempt (started when the signer's success
    /// count was `successes_at_start`) was refused. If the signer has
    /// succeeded since, it is queued again at once; otherwise it waits for
    /// the next success. Returns whether it was queued again.
    pub fn park(&mut self, job: J, successes_at_start: u64) -> bool {
        self.requeue_or_park(Parked {
            job,
            successes_at_start,
        })
    }

    fn requeue_or_park(&mut self, p: Parked<J>) -> bool {
        if self.successes > p.successes_at_start {
            self.stack.push(Queued {
                job: p.job,
                attempt: Attempt::AfterSignerSuccess,
            });
            true
        } else {
            self.parked.push(p);
            false
        }
    }

    /// Drop every queued and parked job and start a new slot generation (an
    /// identity switch). Running jobs finish on their own and release
    /// nothing.
    pub fn reset(&mut self) {
        self.generation += 1;
        self.active = 0;
        self.stack.clear();
        self.parked.clear();
        self.successes = 0;
        self.signer = SignerKind::Local;
    }

    /// Jobs running now.
    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.active
    }

    /// Jobs waiting to start.
    #[cfg(test)]
    pub fn queued(&self) -> usize {
        self.stack.len()
    }

    /// Refused jobs waiting for a signer success.
    #[cfg(test)]
    pub fn parked(&self) -> usize {
        self.parked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_order(q: &mut WrapQueue<u32>) -> Vec<u32> {
        let mut out = Vec::new();
        while let Some(s) = q.start_next() {
            out.push(s.job);
            q.release(s.slot);
        }
        out
    }

    #[test]
    fn newest_queued_runs_first() {
        let mut q = WrapQueue::new();
        // A page delivered newest (1) to oldest (5), then a live wrap (9).
        for j in [1, 2, 3, 4, 5, 9] {
            q.push(j);
        }
        assert_eq!(drain_order(&mut q), vec![9, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn at_most_four_run_at_once() {
        let mut q = WrapQueue::new();
        for j in 0..10 {
            q.push(j);
        }
        let started: Vec<_> = std::iter::from_fn(|| q.start_next()).collect();
        assert_eq!(started.len(), MAX_CONCURRENT_UNWRAPS);
        assert_eq!(q.active(), 4);
        q.release(started[0].slot);
        assert!(q.start_next().is_some());
        assert!(q.start_next().is_none());
    }

    /// One NIP-07 prompt at a time until the extension has decrypted once.
    #[test]
    fn a_refusable_signer_gets_one_slot_until_it_succeeds() {
        let mut q = WrapQueue::new();
        q.set_signer(SignerKind::CanRefuse);
        for j in 0..10 {
            q.push(j);
        }
        let first = q.start_next().unwrap();
        assert!(q.start_next().is_none(), "one prompt, not four");
        q.signer_succeeded();
        q.release(first.slot);
        assert_eq!(std::iter::from_fn(|| q.start_next()).count(), 4);
    }

    /// Finding 4: a switch must not leave the old sign-in's running jobs
    /// counted against the new one, nor let them free the new one's slots.
    #[test]
    fn a_reset_starts_a_new_slot_generation() {
        let mut q = WrapQueue::new();
        for j in 0..8 {
            q.push(j);
        }
        let old: Vec<_> = std::iter::from_fn(|| q.start_next()).collect();
        assert_eq!(q.active(), 4);
        q.reset();
        assert_eq!((q.active(), q.queued()), (0, 0));
        for j in 100..108 {
            q.push(j);
        }
        let new: Vec<_> = std::iter::from_fn(|| q.start_next()).collect();
        assert_eq!(new.len(), 4);
        // The old jobs finish now: they free nothing of the new generation.
        for s in old {
            q.release(s.slot);
        }
        assert_eq!(q.active(), 4);
        assert!(q.start_next().is_none());
    }

    /// Releasing a slot twice (finished after its timeout already released
    /// it) is the store's to prevent; the queue never goes below zero.
    #[test]
    fn release_never_underflows() {
        let mut q: WrapQueue<u32> = WrapQueue::new();
        q.release(Slot { generation: 0 });
        assert_eq!(q.active(), 0);
    }

    #[test]
    fn a_refused_job_waits_for_a_signer_success_then_runs_once_more() {
        let mut q = WrapQueue::new();
        q.set_signer(SignerKind::CanRefuse);
        q.push(7);
        let s = q.start_next().unwrap();
        assert_eq!(s.attempt, Attempt::First);
        q.release(s.slot);
        assert!(!q.park(s.job, s.successes_at_start));
        assert_eq!((q.parked(), q.queued()), (1, 0));
        assert!(q.start_next().is_none(), "nothing to run until a success");
        assert_eq!(q.signer_succeeded(), 1);
        assert_eq!(q.parked(), 0);
        let again = q.start_next().unwrap();
        assert_eq!((again.job, again.attempt), (7, Attempt::AfterSignerSuccess));
    }

    /// The signer succeeded on another wrap while this one was running and
    /// being refused (a denied prompt, then an approved one): it is queued
    /// again at once rather than waiting for yet another success.
    #[test]
    fn a_success_during_the_refused_attempt_requeues_at_once() {
        let mut q = WrapQueue::new();
        q.set_signer(SignerKind::CanRefuse);
        q.signer_succeeded(); // the origin is trusted now; four slots
        q.push(1);
        q.push(2);
        let a = q.start_next().unwrap();
        let b = q.start_next().unwrap();
        q.signer_succeeded(); // b opened
        q.release(b.slot);
        q.release(a.slot);
        assert!(q.park(a.job, a.successes_at_start));
        assert_eq!(q.parked(), 0);
        assert_eq!(q.start_next().unwrap().attempt, Attempt::AfterSignerSuccess);
    }

    #[test]
    fn a_reset_drops_parked_jobs() {
        let mut q = WrapQueue::new();
        q.park(1, 0);
        q.reset();
        assert_eq!(q.signer_succeeded(), 0);
        assert!(q.start_next().is_none());
    }
}
