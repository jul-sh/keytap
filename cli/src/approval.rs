//! Arbitration for concurrent native and nearby passkey approvals.
//!
//! Both routes may produce a fully verified candidate, but exactly one route
//! may cross the acceptance boundary. Cancellation only cleans up the losing
//! UI/transport; the mutex-protected state transition is what prevents
//! duplicate acceptance, output, or acknowledgements when both authenticators
//! finish at nearly the same time.

use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalRoute {
    Native,
    Nearby,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClaimOutcome {
    Claimed,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalState {
    Pending,
    Claimed { winner: ApprovalRoute },
}

pub(crate) struct ApprovalRace {
    state: Mutex<ApprovalState>,
}

impl ApprovalRace {
    pub(crate) fn pending() -> Self {
        Self {
            state: Mutex::new(ApprovalState::Pending),
        }
    }

    pub(crate) fn claim(&self, route: ApprovalRoute) -> ClaimOutcome {
        let mut state = self
            .state
            .lock()
            .expect("approval race state mutex was poisoned");

        match (*state, route) {
            (ApprovalState::Pending, route) => {
                *state = ApprovalState::Claimed { winner: route };
                ClaimOutcome::Claimed
            }
            (
                ApprovalState::Claimed {
                    winner: ApprovalRoute::Native,
                },
                ApprovalRoute::Nearby,
            ) => ClaimOutcome::Lost,
            (
                ApprovalState::Claimed {
                    winner: ApprovalRoute::Nearby,
                },
                ApprovalRoute::Native,
            ) => ClaimOutcome::Lost,
            (ApprovalState::Claimed { winner }, duplicate) => {
                // Do not poison the mutex when reporting a caller invariant violation.
                drop(state);
                panic!(
                    "approval route {duplicate:?} attempted a duplicate claim after {winner:?} won"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn first_claim_wins_and_the_competing_route_observes_it() {
        let race = ApprovalRace::pending();
        assert_eq!(race.claim(ApprovalRoute::Nearby), ClaimOutcome::Claimed);
        assert_eq!(race.claim(ApprovalRoute::Native), ClaimOutcome::Lost);
    }

    #[test]
    fn a_duplicate_claim_by_the_winning_route_is_an_invariant_violation() {
        let race = ApprovalRace::pending();
        assert_eq!(race.claim(ApprovalRoute::Native), ClaimOutcome::Claimed);

        let duplicate = std::panic::catch_unwind(|| race.claim(ApprovalRoute::Native));
        assert!(duplicate.is_err());

        // The explicit invariant panic happens after releasing the lock, so the
        // state remains usable and the competing route still observes the winner.
        assert_eq!(race.claim(ApprovalRoute::Nearby), ClaimOutcome::Lost);
    }

    #[test]
    fn simultaneous_candidates_produce_exactly_one_winner() {
        let race = Arc::new(ApprovalRace::pending());
        let barrier = Arc::new(Barrier::new(3));
        let mut contenders = Vec::new();
        for route in [ApprovalRoute::Native, ApprovalRoute::Nearby] {
            let race = Arc::clone(&race);
            let barrier = Arc::clone(&barrier);
            contenders.push(std::thread::spawn(move || {
                barrier.wait();
                (route, race.claim(route))
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = contenders
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, outcome)| matches!(outcome, ClaimOutcome::Claimed))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, outcome)| matches!(outcome, ClaimOutcome::Lost))
                .count(),
            1
        );
    }
}
