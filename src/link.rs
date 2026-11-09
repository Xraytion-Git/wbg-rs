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
