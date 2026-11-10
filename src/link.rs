//! Profile-transition state machine adapted from logixism/open-wbg-service
//! src/linking.rs (MIT, SOLO ❯ CODES). Semantics preserved verbatim:
//! - own only automatic transitions; never undo a physical Mode/Cycle press
//! - a failed HID transaction is not committed
//! - leaving a linked profile restores the user's actual onboard baseline

use crate::ff55::ProfileId;

#[derive(Clone, Debug)]
pub struct LinkState {
    pub target: Option<ProfileId>,
    pub baseline: ProfileId,
}

pub struct Transition {
    pub selection: Option<Option<ProfileId>>,
    pub activate: Option<ProfileId>,
    pub next: LinkState,
}

impl LinkState {
    pub fn new(current: ProfileId, fallback: u8) -> Self {
        Self {
            target: None,
            baseline: if current.namespace == 0 {
                current
            } else {
                ProfileId {
                    namespace: 0,
                    index: fallback,
                }
            },
        }
    }

    pub fn plan(&self, current: ProfileId, desired: Option<ProfileId>) -> Option<Transition> {
        if self.target == desired {
            return None;
        }
        let mut next = self.clone();
        // An onboard profile different from our own target is a user's selection.
        if current.namespace == 0 && self.target != Some(current) {
            next.baseline = current;
        }
        next.target = desired;
        let selection = if desired.is_some_and(|id| id.namespace == 1) {
            Some(desired)
        } else if self.target.is_some_and(|id| id.namespace == 1) {
            Some(None)
        } else {
            None
        };
        let activate = match desired {
            Some(id) => (current != id).then_some(id),
            None if self.target == Some(current) || current.namespace == 1 => Some(next.baseline),
            None => None,
        };
        Some(Transition {
            selection,
            activate,
            next,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(ns: u8, idx: u8) -> ProfileId {
        ProfileId {
            namespace: ns,
            index: idx,
        }
    }

    #[test]
    fn new_uses_current_as_baseline_when_onboard() {
        let s = LinkState::new(pid(0, 3), 0);
        assert_eq!(s.baseline, pid(0, 3));
        assert_eq!(s.target, None);
    }

    #[test]
    fn new_uses_fallback_when_linked() {
        let s = LinkState::new(pid(1, 0), 2);
        assert_eq!(s.baseline, pid(0, 2));
        assert_eq!(s.target, None);
    }

    #[test]
    fn no_transition_when_target_unchanged() {
        let s = LinkState::new(pid(0, 0), 0);
        let t = s.plan(pid(0, 0), Some(pid(1, 0))).unwrap();
        // Second plan with the same desired target must be a no-op.
        assert!(t.next.plan(pid(1, 0), Some(pid(1, 0))).is_none());
    }

    #[test]
    fn switch_to_linked_profile() {
        let s = LinkState::new(pid(0, 0), 0);
        let t = s.plan(pid(0, 0), Some(pid(1, 0))).unwrap();
        assert_eq!(t.selection, Some(Some(pid(1, 0))));
        assert_eq!(t.activate, Some(pid(1, 0)));
    }

    #[test]
    fn manual_switch_updates_baseline() {
        let mut s = LinkState::new(pid(0, 0), 0);
        s.target = Some(pid(1, 0)); // game running on linked 1/0
        // User pressed Mode and moved to onboard 0/3; game then closes.
        let t = s.plan(pid(0, 3), None).unwrap();
        assert_eq!(t.next.baseline, pid(0, 3));
        assert_eq!(t.activate, None); // already on the manual selection
    }

    #[test]
    fn return_to_baseline_after_game() {
        let mut s = LinkState::new(pid(0, 2), 0);
        s.target = Some(pid(1, 0));
        // Game closes while still on the linked profile.
        let t = s.plan(pid(1, 0), None).unwrap();
        assert_eq!(t.selection, Some(None)); // deselect linked
        assert_eq!(t.activate, Some(pid(0, 2))); // restore baseline
    }

    #[test]
    fn switching_games_keeps_manual_baseline() {
        let mut s = LinkState::new(pid(0, 0), 0);
        s.target = Some(pid(1, 0));
        // User manually chose 0/5 during game 1; game 2 starts on 1/1.
        let t = s.plan(pid(0, 5), Some(pid(1, 1))).unwrap();
        assert_eq!(t.next.baseline, pid(0, 5));
        assert_eq!(t.activate, Some(pid(1, 1)));
    }
}
