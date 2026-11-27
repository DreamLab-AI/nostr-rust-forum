//! Readiness of encrypted-zone search, as a search UI shows it.
//!
//! Pure state: [`ZoneLoad`] is where one zone's index load stands,
//! [`aggregate`] folds the zones into one [`Readiness`], and [`before_load`]
//! gives the state while no load can start yet. The browser side
//! (`sealed_search.rs`) keeps the per-zone states and publishes the aggregate
//! as a signal.

use std::fmt;

/// Why encrypted-zone search cannot answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No zone is set up for sealed search, or no index publisher is configured.
    NotConfigured,
    /// Nobody is signed in.
    SignedOut,
    /// The member holds no key for any zone with sealed search.
    NoKeys,
    /// No publisher has an index this member can open.
    NoIndex,
    /// Loading failed; the reason is for the console and the notice.
    Failed(String),
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("Encrypted zones are not set up for search."),
            Self::SignedOut => f.write_str("Sign in to search encrypted zones."),
            Self::NoKeys => f.write_str("You hold no key for an encrypted zone."),
            Self::NoIndex => {
                f.write_str("No search index has been published for your encrypted zones.")
            }
            Self::Failed(why) => write!(f, "Encrypted zones could not be searched: {why}"),
        }
    }
}

/// Where encrypted-zone search stands, across every zone this member can search.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Readiness {
    /// Nothing has started: the loader has not run yet in this session.
    #[default]
    Idle,
    /// Indexes are on their way. `loaded` of `total` shards are searchable
    /// (`total` is 0 until the manifests are read); results found meanwhile
    /// come from the loaded shards only, so they are partial.
    Loading {
        /// Shards searchable so far.
        loaded: u32,
        /// Shards to load (0 while the manifests are still being read).
        total: u32,
    },
    /// Every index this member can open is loaded.
    Ready,
    /// Nothing can be searched, and why.
    Unavailable(Unavailable),
}

impl Readiness {
    /// Whether loading is still under way.
    pub fn is_loading(&self) -> bool {
        matches!(self, Self::Loading { .. })
    }

    /// Whether results found now may be missing matches that are still loading.
    pub fn is_partial(&self) -> bool {
        self.is_loading()
    }

    /// Whether a search UI must not say "no results" for a message search:
    /// an empty answer now may only mean the index has not arrived.
    pub fn hides_no_results(&self) -> bool {
        self.is_loading()
    }

    /// The line a search UI shows while results are or may be partial, if any.
    pub fn notice(&self) -> Option<String> {
        match self {
            Self::Loading { total: 0, .. } => {
                Some("Encrypted zones are still loading; results will appear here.".into())
            }
            Self::Loading { loaded, total } => Some(format!(
                "Encrypted zones are still loading ({loaded} of {total} parts); results so far may be incomplete."
            )),
            _ => None,
        }
    }
}

/// Where one zone's index load stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneLoad {
    /// Started: reading the manifest.
    Pending,
    /// `loaded` of `total` shards are in the worker.
    Loading {
        /// Shards in the worker.
        loaded: u32,
        /// Shards this member can open.
        total: u32,
    },
    /// Every shard this member can open is in the worker.
    Ready,
    /// Every publisher answered and none has an index this member can open.
    NoIndex,
    /// The load stopped; shards already loaded stay searchable.
    Failed(String),
}

/// One [`Readiness`] for every zone being loaded or loaded.
///
/// Loading while any zone is still under way (shards summed across zones);
/// then ready if any zone loaded, else the first failure, else no index.
/// A zone without an index never holds the others back: one ready zone and
/// several without an index is ready.
pub fn aggregate<'a>(zones: impl IntoIterator<Item = &'a ZoneLoad>) -> Readiness {
    let (mut busy, mut any_ready, mut any) = (false, false, false);
    let (mut loaded, mut total) = (0u32, 0u32);
    let mut failure: Option<&str> = None;
    for z in zones {
        any = true;
        match z {
            ZoneLoad::Pending => busy = true,
            ZoneLoad::Loading {
                loaded: l,
                total: t,
            } => {
                busy = true;
                loaded += l;
                total += t;
            }
            ZoneLoad::Ready => any_ready = true,
            ZoneLoad::NoIndex => {}
            ZoneLoad::Failed(why) => {
                failure.get_or_insert(why);
            }
        }
    }
    if !any {
        Readiness::Idle
    } else if busy {
        Readiness::Loading { loaded, total }
    } else if any_ready {
        Readiness::Ready
    } else if let Some(why) = failure {
        Readiness::Unavailable(Unavailable::Failed(why.to_string()))
    } else {
        Readiness::Unavailable(Unavailable::NoIndex)
    }
}

/// The state while no load can start, or `None` when one should start.
///
/// `configured`: a sealed zone and a publisher are configured; `signed_in`:
/// an identity is signed in; `keys_ready`: its stored zone keys are read;
/// `holds_key`: one of them is for a sealed zone.
pub fn before_load(
    configured: bool,
    signed_in: bool,
    keys_ready: bool,
    holds_key: bool,
) -> Option<Readiness> {
    if !configured {
        Some(Readiness::Unavailable(Unavailable::NotConfigured))
    } else if !signed_in {
        Some(Readiness::Unavailable(Unavailable::SignedOut))
    } else if !keys_ready {
        // The keys are being read: a search typed now must wait, not be told
        // there is nothing.
        Some(Readiness::Loading {
            loaded: 0,
            total: 0,
        })
    } else if !holds_key {
        Some(Readiness::Unavailable(Unavailable::NoKeys))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loading(loaded: u32, total: u32) -> ZoneLoad {
        ZoneLoad::Loading { loaded, total }
    }

    #[test]
    fn nothing_started_is_idle() {
        assert_eq!(aggregate([]), Readiness::Idle);
    }

    #[test]
    fn one_ready_zone_beside_zones_without_an_index_is_ready() {
        // The live shape: zone2 has an index; four other sealed zones have none.
        let zones = [
            ZoneLoad::Ready,
            ZoneLoad::NoIndex,
            ZoneLoad::NoIndex,
            ZoneLoad::NoIndex,
            ZoneLoad::NoIndex,
        ];
        assert_eq!(aggregate(&zones), Readiness::Ready);
    }

    #[test]
    fn loading_sums_shards_and_waits_for_every_zone() {
        let zones = [loading(3, 8), ZoneLoad::Ready, loading(1, 2)];
        assert_eq!(
            aggregate(&zones),
            Readiness::Loading {
                loaded: 4,
                total: 10
            }
        );
        // A manifest still being read keeps it loading, total not yet known.
        assert_eq!(
            aggregate(&[ZoneLoad::Pending, ZoneLoad::NoIndex]),
            Readiness::Loading {
                loaded: 0,
                total: 0
            }
        );
    }

    #[test]
    fn the_load_walks_from_pending_through_shards_to_ready() {
        let mut z = ZoneLoad::Pending;
        let mut seen = vec![aggregate([&z])];
        for loaded in 0..=3 {
            z = loading(loaded, 3);
            seen.push(aggregate([&z]));
        }
        z = ZoneLoad::Ready;
        seen.push(aggregate([&z]));
        assert_eq!(
            seen,
            [
                Readiness::Loading {
                    loaded: 0,
                    total: 0
                },
                Readiness::Loading {
                    loaded: 0,
                    total: 3
                },
                Readiness::Loading {
                    loaded: 1,
                    total: 3
                },
                Readiness::Loading {
                    loaded: 2,
                    total: 3
                },
                Readiness::Loading {
                    loaded: 3,
                    total: 3
                },
                Readiness::Ready,
            ]
        );
        assert!(seen[2].is_partial() && seen[2].hides_no_results());
        assert!(!seen[5].is_partial() && !seen[5].hides_no_results());
    }

    #[test]
    fn a_failure_is_reported_only_when_nothing_loaded() {
        assert_eq!(
            aggregate(&[ZoneLoad::Failed("HTTP 500".into()), ZoneLoad::NoIndex]),
            Readiness::Unavailable(Unavailable::Failed("HTTP 500".into()))
        );
        assert_eq!(
            aggregate(&[ZoneLoad::Failed("HTTP 500".into()), ZoneLoad::Ready]),
            Readiness::Ready
        );
        assert_eq!(
            aggregate(&[ZoneLoad::NoIndex, ZoneLoad::NoIndex]),
            Readiness::Unavailable(Unavailable::NoIndex)
        );
    }

    #[test]
    fn before_a_load_can_start() {
        use Unavailable::*;
        let u = Readiness::Unavailable;
        assert_eq!(before_load(false, true, true, true), Some(u(NotConfigured)));
        assert_eq!(before_load(true, false, false, false), Some(u(SignedOut)));
        assert_eq!(
            before_load(true, true, false, false),
            Some(Readiness::Loading {
                loaded: 0,
                total: 0
            }),
            "keys still being read: wait, do not say there is nothing"
        );
        assert_eq!(before_load(true, true, true, false), Some(u(NoKeys)));
        assert_eq!(before_load(true, true, true, true), None);
    }

    #[test]
    fn only_loading_hides_no_results_and_shows_a_notice() {
        let l0 = Readiness::Loading {
            loaded: 0,
            total: 0,
        };
        let l = Readiness::Loading {
            loaded: 2,
            total: 8,
        };
        assert!(l0.hides_no_results() && l.hides_no_results());
        assert!(l.notice().unwrap().contains("2 of 8"));
        assert!(l0.notice().is_some());
        for r in [
            Readiness::Idle,
            Readiness::Ready,
            Readiness::Unavailable(Unavailable::NoKeys),
        ] {
            assert!(!r.hides_no_results(), "{r:?}");
            assert_eq!(r.notice(), None);
        }
    }
}
