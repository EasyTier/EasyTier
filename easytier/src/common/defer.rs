#[doc(hidden)]
pub struct Defer<F: FnOnce()> {
    // internal struct used by defer! macro
    func: Option<F>,
}

impl<F: FnOnce()> Defer<F> {
    pub fn new(func: F) -> Self {
        Self { func: Some(func) }
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.func.take() {
            f()
        }
    }
}

#[macro_export]
macro_rules! defer {
	( $($tt:tt)* ) => {
		let _deferred = $crate::common::defer::Defer::new(|| { $($tt)* });
	};
}
