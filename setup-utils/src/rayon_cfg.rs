cfg_if::cfg_if! {
    if #[cfg(not(feature = "parallel"))] {
        pub struct ScopeShim {}

        impl ScopeShim {
            pub fn spawn<F: FnOnce(&ScopeShim) + Send>(&self, func: F) {
                func(&self);
            }
        }

        pub fn scope<OP, R>(op: OP) -> R
        where
            OP: FnOnce(&ScopeShim) -> R + Send,
            R: Send {
            let scope = ScopeShim {};
            op(&scope)
        }
    } else {
        pub fn scope<'scope, OP, R>(op: OP) -> R
        where
            OP: for<'s> FnOnce(&'s rayon::Scope<'scope>) -> R + 'scope + Send,
            R: Send {
            rayon::scope(op)
        }
    }
}
