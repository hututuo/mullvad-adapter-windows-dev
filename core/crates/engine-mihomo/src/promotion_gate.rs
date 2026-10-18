//! Keep time-sensitive evidence checks adjacent to durable commit and selection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Stale,
    Commit,
    Selection,
}
pub(crate) fn promote(
    fresh: impl Fn() -> bool,
    commit: impl FnOnce() -> bool,
    select: impl FnOnce() -> bool,
) -> Result<(), Error> {
    if !fresh() {
        return Err(Error::Stale);
    }
    if !commit() {
        return Err(Error::Commit);
    }
    if !fresh() {
        return Err(Error::Stale);
    }
    if !select() {
        return Err(Error::Selection);
    }
    if !fresh() {
        return Err(Error::Stale);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn expired_before_or_during_storage_never_selects_the_candidate() {
        for expire_during_commit in [false, true] {
            let fresh = Cell::new(expire_during_commit);
            let commits = Cell::new(0);
            let selections = Cell::new(0);
            assert_eq!(
                promote(
                    || fresh.get(),
                    || {
                        commits.set(commits.get() + 1);
                        fresh.set(false);
                        true
                    },
                    || {
                        selections.set(selections.get() + 1);
                        true
                    }
                ),
                Err(Error::Stale)
            );
            assert_eq!(commits.get(), if expire_during_commit { 1 } else { 0 });
            assert_eq!(selections.get(), 0);
        }
    }
    #[test]
    fn failed_storage_and_late_selection_fail_closed_without_relabeling_stale() {
        let selected = Cell::new(false);
        assert_eq!(
            promote(
                || true,
                || false,
                || {
                    selected.set(true);
                    true
                }
            ),
            Err(Error::Commit)
        );
        assert!(!selected.get());
        let fresh = Cell::new(true);
        assert_eq!(
            promote(
                || fresh.get(),
                || true,
                || {
                    fresh.set(false);
                    true
                }
            ),
            Err(Error::Stale)
        );
        assert_eq!(promote(|| true, || true, || false), Err(Error::Selection));
        assert_eq!(promote(|| true, || true, || true), Ok(()));
    }
}
