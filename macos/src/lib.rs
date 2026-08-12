use std::ffi::c_void;
use std::sync::{Arc, Mutex};

#[derive(Debug, Eq, PartialEq)]
pub enum RegistrationOutcome {
    Success {
        /// WebAuthn credential ID of the newly registered passkey. Stable
        /// registration-level material, suitable for fingerprinting the root.
        credential_id: Vec<u8>,
    },
    Cancelled,
    /// The native request produced no credential result, so another
    /// authenticator may safely be tried.
    Unavailable {
        message: String,
    },
    /// Native registration may have created a credential. Starting another
    /// registration automatically could therefore create a second root.
    Indeterminate {
        message: String,
    },
}

pub enum AssertionOutcome {
    Success {
        prf_output: Vec<u8>,
        /// Credential ID of the passkey that produced this assertion.
        credential_id: Vec<u8>,
    },
    Cancelled,
    Error(String),
}

pub enum AssertionCredential {
    Discoverable,
    Constrained { credential_id: Vec<u8> },
}

/// A native assertion that has not started its AppKit run loop yet.
pub struct AssertionOperation {
    control: Arc<OperationControl>,
    prf_salt: [u8; 32],
    credential: AssertionCredential,
}

impl AssertionOperation {
    pub fn new(prf_salt: [u8; 32], credential: AssertionCredential) -> Self {
        Self {
            control: OperationControl::new(),
            prf_salt,
            credential,
        }
    }

    pub fn cancellation_handle(&self) -> CancellationHandle {
        CancellationHandle {
            control: Arc::clone(&self.control),
        }
    }

    /// Run the native passkey assertion on the process main thread.
    pub fn run(self) -> AssertionOutcome {
        let (credential_mode, credential_id_ptr, credential_id_len) = match &self.credential {
            AssertionCredential::Discoverable => (CREDENTIAL_DISCOVERABLE, std::ptr::null(), 0),
            AssertionCredential::Constrained { credential_id } => {
                if let Err(error) = validate_length(
                    credential_id.len(),
                    "credential ID",
                    ExpectedLength::Inclusive {
                        minimum: 1,
                        maximum: MAX_CREDENTIAL_ID_BYTES,
                    },
                ) {
                    self.control.finish();
                    return AssertionOutcome::Error(error);
                }
                (
                    CREDENTIAL_CONSTRAINED,
                    credential_id.as_ptr(),
                    credential_id.len(),
                )
            }
        };

        let mut context = AssertionCallbackContext::new(Arc::clone(&self.control));

        // SAFETY: Swift's bridge entry point has a synchronous, blocking ABI.
        // It invokes exactly one terminal callback before returning and never
        // retains or invokes either callback afterward. `context` and both
        // input slices therefore remain alive for the entire foreign call.
        // Callback byte buffers are borrowed only for the callback duration;
        // the callback implementations below validate and copy them before
        // returning to Swift.
        unsafe {
            keytap_assert(
                self.prf_salt.as_ptr(),
                self.prf_salt.len(),
                credential_mode,
                credential_id_ptr,
                credential_id_len,
                ffi_context_ptr(&mut context),
                on_controller_ready,
                on_assertion,
            );
        }

        context.into_outcome()
    }
}

/// A thread-safe request to dismiss one native passkey assertion.
///
/// Calling this before [`AssertionOperation::run`] is safe: the request is
/// delivered as soon as Swift has retained the authorization controller.
/// Repeated and late calls are no-ops.
#[derive(Clone)]
pub struct CancellationHandle {
    control: Arc<OperationControl>,
}

impl CancellationHandle {
    pub fn cancel(&self) {
        match self.control.request_cancellation() {
            CancellationAction::Dispatch => {
                // SAFETY: Each CLI process owns at most one native assertion.
                // Swift ignores cancellation when no assertion is active.
                unsafe { keytap_cancel() };
            }
            CancellationAction::Queued | CancellationAction::Ignored => {}
        }
    }
}

/// Runs the native macOS passkey registration ceremony. Blocks until the user
/// completes or cancels it.
pub fn register() -> RegistrationOutcome {
    let mut context = CallbackContext::waiting();

    // SAFETY: Swift's bridge entry point has a synchronous, blocking ABI. It
    // invokes exactly one terminal callback before returning and never retains
    // or invokes the callback afterward, so the stack context remains valid.
    // Callback buffers are valid only during the callback and are validated
    // and copied before control returns to Swift.
    unsafe {
        keytap_register(ffi_context_ptr(&mut context), on_registration);
    }

    context.into_outcome(|| RegistrationOutcome::Indeterminate {
        message: "native passkey bridge returned without a terminal callback".into(),
    })
}

type ControllerReadyCallback = unsafe extern "C" fn(context: *mut c_void);
type RawCallback = unsafe extern "C" fn(
    context: *mut c_void,
    status: i32,
    data: *const u8,
    data_len: usize,
    extra: *const u8,
    extra_len: usize,
);

extern "C" {
    fn keytap_register(context: *mut c_void, callback: RawCallback);
    fn keytap_assert(
        salt_ptr: *const u8,
        salt_len: usize,
        credential_mode: i32,
        credential_id_ptr: *const u8,
        credential_id_len: usize,
        context: *mut c_void,
        controller_ready: ControllerReadyCallback,
        callback: RawCallback,
    );
    fn keytap_cancel();
}

const STATUS_SUCCESS: i32 = 0;
const STATUS_ERROR: i32 = 1;
const STATUS_CANCELLED: i32 = 2;
const STATUS_UNAVAILABLE: i32 = 3;
const CREDENTIAL_DISCOVERABLE: i32 = 0;
const CREDENTIAL_CONSTRAINED: i32 = 1;

const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const PRF_OUTPUT_BYTES: usize = 32;
const MAX_ERROR_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationState {
    Preparing,
    CancellationQueued,
    ControllerReady,
    CancellationDispatched,
    Finished,
}

enum CancellationAction {
    Queued,
    Dispatch,
    Ignored,
}

enum ControllerReadyAction {
    AwaitCompletion,
    DispatchCancellation,
    Ignored,
}

struct OperationControl {
    state: Mutex<OperationState>,
}

impl OperationControl {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(OperationState::Preparing),
        })
    }

    fn request_cancellation(&self) -> CancellationAction {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *state {
            OperationState::Preparing => {
                *state = OperationState::CancellationQueued;
                CancellationAction::Queued
            }
            OperationState::ControllerReady => {
                *state = OperationState::CancellationDispatched;
                CancellationAction::Dispatch
            }
            OperationState::CancellationQueued | OperationState::CancellationDispatched => {
                CancellationAction::Ignored
            }
            OperationState::Finished => CancellationAction::Ignored,
        }
    }

    fn controller_ready(&self) -> ControllerReadyAction {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *state {
            OperationState::Preparing => {
                *state = OperationState::ControllerReady;
                ControllerReadyAction::AwaitCompletion
            }
            OperationState::CancellationQueued => {
                *state = OperationState::CancellationDispatched;
                ControllerReadyAction::DispatchCancellation
            }
            OperationState::ControllerReady | OperationState::CancellationDispatched => {
                ControllerReadyAction::Ignored
            }
            OperationState::Finished => ControllerReadyAction::Ignored,
        }
    }

    fn finish(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = OperationState::Finished;
    }

    #[cfg(test)]
    fn state(&self) -> OperationState {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

enum CallbackState<T> {
    Waiting,
    Completed(T),
}

struct CallbackContext<T> {
    state: CallbackState<T>,
}

impl<T> CallbackContext<T> {
    fn waiting() -> Self {
        Self {
            state: CallbackState::Waiting,
        }
    }

    /// Keep the first terminal callback. Swift also guarantees a single
    /// terminal callback, while this boundary prevents a bridge bug from
    /// replacing an already-copied outcome during the synchronous call.
    fn complete_with(&mut self, make_outcome: impl FnOnce() -> T) {
        match self.state {
            CallbackState::Waiting => {
                self.state = CallbackState::Completed(make_outcome());
            }
            CallbackState::Completed(_) => {}
        }
    }

    fn into_outcome(self, missing: impl FnOnce() -> T) -> T {
        match self.state {
            CallbackState::Waiting => missing(),
            CallbackState::Completed(outcome) => outcome,
        }
    }
}

struct AssertionCallbackContext {
    control: Arc<OperationControl>,
    completion: CallbackContext<AssertionOutcome>,
}

impl AssertionCallbackContext {
    fn new(control: Arc<OperationControl>) -> Self {
        Self {
            control,
            completion: CallbackContext::waiting(),
        }
    }

    fn into_outcome(self) -> AssertionOutcome {
        let Self {
            control,
            completion,
        } = self;
        completion.into_outcome(|| {
            control.finish();
            AssertionOutcome::Error(
                "native passkey bridge returned without a terminal callback".into(),
            )
        })
    }
}

fn ffi_context_ptr<T>(context: &mut T) -> *mut c_void {
    std::ptr::from_mut(context).cast()
}

unsafe extern "C" fn on_controller_ready(raw: *mut c_void) {
    // SAFETY: Swift passes back the same live pointer supplied to
    // `keytap_assert`, and does so only during that blocking call.
    let Some(context) = (unsafe { raw.cast::<AssertionCallbackContext>().as_mut() }) else {
        return;
    };
    let action = context.control.controller_ready();

    // The context borrow ends before crossing FFI, so even a foreign bridge
    // regression cannot create a re-entrant mutable reference to it here.
    match action {
        ControllerReadyAction::DispatchCancellation => {
            // SAFETY: Swift just announced the process's only assertion
            // controller. It ignores cancellation if that assertion finished.
            unsafe { keytap_cancel() };
        }
        ControllerReadyAction::AwaitCompletion | ControllerReadyAction::Ignored => {}
    }
}

unsafe extern "C" fn on_registration(
    raw: *mut c_void,
    status: i32,
    data: *const u8,
    data_len: usize,
    extra: *const u8,
    extra_len: usize,
) {
    // SAFETY: Swift passes back the same live pointer supplied to
    // `keytap_register`, and does so only during that blocking call.
    let Some(context) = (unsafe { raw.cast::<CallbackContext<RegistrationOutcome>>().as_mut() })
    else {
        return;
    };

    context.complete_with(|| registration_outcome_from_callback(status, data, data_len, extra_len));

    // `extra` is intentionally not dereferenced: registration has no secondary
    // payload. A non-zero length is classified as an indeterminate malformed
    // response above.
    let _ = extra;
}

fn registration_outcome_from_callback(
    status: i32,
    data: *const u8,
    data_len: usize,
    extra_len: usize,
) -> RegistrationOutcome {
    if extra_len != 0 {
        return RegistrationOutcome::Indeterminate {
            message: "native passkey bridge returned unexpected registration payload".into(),
        };
    }

    match status {
        STATUS_SUCCESS => {
            match copy_bytes(
                data,
                data_len,
                "credential ID",
                ExpectedLength::Inclusive {
                    minimum: 1,
                    maximum: MAX_CREDENTIAL_ID_BYTES,
                },
            ) {
                Ok(credential_id) => RegistrationOutcome::Success { credential_id },
                Err(message) => RegistrationOutcome::Indeterminate { message },
            }
        }
        STATUS_CANCELLED if data_len == 0 => RegistrationOutcome::Cancelled,
        STATUS_CANCELLED => RegistrationOutcome::Indeterminate {
            message: "native passkey bridge returned an unexpected cancellation payload".into(),
        },
        STATUS_UNAVAILABLE => match copy_registration_message(data, data_len) {
            Ok(message) => RegistrationOutcome::Unavailable { message },
            Err(message) => RegistrationOutcome::Indeterminate { message },
        },
        STATUS_ERROR => RegistrationOutcome::Indeterminate {
            message: copy_error(data, data_len),
        },
        status => RegistrationOutcome::Indeterminate {
            message: format!("native passkey bridge returned unknown status {status}"),
        },
    }
}

unsafe extern "C" fn on_assertion(
    raw: *mut c_void,
    status: i32,
    data: *const u8,
    data_len: usize,
    extra: *const u8,
    extra_len: usize,
) {
    // SAFETY: Swift passes back the same live pointer supplied to
    // `keytap_assert`, and does so only during that blocking call.
    let Some(context) = (unsafe { raw.cast::<AssertionCallbackContext>().as_mut() }) else {
        return;
    };
    let control = Arc::clone(&context.control);

    context.completion.complete_with(|| match status {
        STATUS_SUCCESS => {
            control.finish();
            match (
                copy_bytes(
                    data,
                    data_len,
                    "credential ID",
                    ExpectedLength::Inclusive {
                        minimum: 1,
                        maximum: MAX_CREDENTIAL_ID_BYTES,
                    },
                ),
                copy_bytes(
                    extra,
                    extra_len,
                    "PRF output",
                    ExpectedLength::Exact(PRF_OUTPUT_BYTES),
                ),
            ) {
                (Ok(credential_id), Ok(prf_output)) => AssertionOutcome::Success {
                    prf_output,
                    credential_id,
                },
                (Err(error), _) | (_, Err(error)) => AssertionOutcome::Error(error),
            }
        }
        STATUS_CANCELLED => {
            control.finish();
            AssertionOutcome::Cancelled
        }
        STATUS_ERROR => {
            control.finish();
            AssertionOutcome::Error(copy_error(data, data_len))
        }
        status => {
            control.finish();
            AssertionOutcome::Error(format!(
                "native passkey bridge returned unknown status {status}"
            ))
        }
    });
}

#[derive(Clone, Copy)]
enum ExpectedLength {
    Inclusive { minimum: usize, maximum: usize },
    Exact(usize),
}

fn validate_length(length: usize, label: &str, expected: ExpectedLength) -> Result<(), String> {
    match expected {
        ExpectedLength::Inclusive {
            minimum,
            maximum: _,
        } if length < minimum => Err(format!(
            "native passkey bridge returned a {label} shorter than {minimum} bytes"
        )),
        ExpectedLength::Inclusive {
            minimum: _,
            maximum,
        } if length > maximum => Err(format!(
            "native passkey bridge returned a {label} longer than {maximum} bytes"
        )),
        ExpectedLength::Inclusive { .. } => Ok(()),
        ExpectedLength::Exact(expected) if length != expected => Err(format!(
            "native passkey bridge returned a {label} with length {length}; expected {expected} bytes"
        )),
        ExpectedLength::Exact(_) => Ok(()),
    }
}

fn copy_bytes(
    pointer: *const u8,
    length: usize,
    label: &str,
    expected: ExpectedLength,
) -> Result<Vec<u8>, String> {
    // Validate attacker-controlled length before constructing a slice. This
    // avoids both oversized allocations and reading beyond the callback buffer.
    validate_length(length, label, expected)?;
    if pointer.is_null() {
        return Err(format!("native passkey bridge returned a null {label}"));
    }

    // SAFETY: After validating the protocol length and non-null pointer, the
    // Swift callback contract guarantees this buffer is readable for `length`
    // bytes until the callback returns. We copy it immediately.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec())
}

fn copy_error(pointer: *const u8, length: usize) -> String {
    if length == 0 {
        return "native passkey ceremony failed".into();
    }
    if length > MAX_ERROR_BYTES {
        return format!(
            "native passkey bridge returned an error message longer than {MAX_ERROR_BYTES} bytes"
        );
    }
    if pointer.is_null() {
        return "native passkey bridge returned a null error message".into();
    }

    // SAFETY: The length is bounded and the pointer is non-null. Swift keeps
    // callback storage alive until this callback returns; copy it now.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(pointer, length) }).into_owned()
}

fn copy_registration_message(pointer: *const u8, length: usize) -> Result<String, String> {
    let bytes = copy_bytes(
        pointer,
        length,
        "registration error message",
        ExpectedLength::Inclusive {
            minimum: 1,
            maximum: MAX_ERROR_BYTES,
        },
    )?;
    String::from_utf8(bytes)
        .map_err(|_| "native passkey bridge returned a non-UTF-8 registration error".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_before_controller_ready_is_dispatched_once() {
        let control = OperationControl::new();
        assert!(matches!(
            control.request_cancellation(),
            CancellationAction::Queued
        ));
        assert_eq!(control.state(), OperationState::CancellationQueued);
        assert!(matches!(
            control.controller_ready(),
            ControllerReadyAction::DispatchCancellation
        ));
        assert_eq!(control.state(), OperationState::CancellationDispatched);
        assert!(matches!(
            control.request_cancellation(),
            CancellationAction::Ignored
        ));
    }

    #[test]
    fn ready_and_late_cancellation_are_idempotent() {
        let control = OperationControl::new();
        assert!(matches!(
            control.controller_ready(),
            ControllerReadyAction::AwaitCompletion
        ));
        assert!(matches!(
            control.request_cancellation(),
            CancellationAction::Dispatch
        ));
        assert!(matches!(
            control.request_cancellation(),
            CancellationAction::Ignored
        ));
        control.finish();
        assert!(matches!(
            control.request_cancellation(),
            CancellationAction::Ignored
        ));
        assert_eq!(control.state(), OperationState::Finished);
    }

    #[test]
    fn first_terminal_callback_wins() {
        let mut context = CallbackContext::waiting();
        context.complete_with(|| 7);
        context.complete_with(|| 11);
        assert_eq!(context.into_outcome(|| 13), 7);
    }

    #[test]
    fn registration_unavailable_is_distinct_from_indeterminate_failure() {
        let unavailable_message = b"provider unavailable";
        assert_eq!(
            registration_outcome_from_callback(
                STATUS_UNAVAILABLE,
                unavailable_message.as_ptr(),
                unavailable_message.len(),
                0,
            ),
            RegistrationOutcome::Unavailable {
                message: "provider unavailable".into(),
            }
        );

        let indeterminate_message = b"credential result malformed";
        assert_eq!(
            registration_outcome_from_callback(
                STATUS_ERROR,
                indeterminate_message.as_ptr(),
                indeterminate_message.len(),
                0,
            ),
            RegistrationOutcome::Indeterminate {
                message: "credential result malformed".into(),
            }
        );
    }

    #[test]
    fn malformed_registration_responses_are_indeterminate() {
        assert!(matches!(
            registration_outcome_from_callback(STATUS_SUCCESS, std::ptr::null(), 0, 0),
            RegistrationOutcome::Indeterminate { .. }
        ));
        assert!(matches!(
            registration_outcome_from_callback(STATUS_CANCELLED, b"x".as_ptr(), 1, 0),
            RegistrationOutcome::Indeterminate { .. }
        ));
        assert!(matches!(
            registration_outcome_from_callback(STATUS_UNAVAILABLE, std::ptr::null(), 0, 0),
            RegistrationOutcome::Indeterminate { .. }
        ));
        assert!(matches!(
            registration_outcome_from_callback(
                STATUS_UNAVAILABLE,
                b"provider unavailable".as_ptr(),
                b"provider unavailable".len(),
                1,
            ),
            RegistrationOutcome::Indeterminate { .. }
        ));
        assert!(matches!(
            registration_outcome_from_callback(99, std::ptr::null(), 0, 0),
            RegistrationOutcome::Indeterminate { .. }
        ));
    }

    #[test]
    fn ffi_lengths_are_checked_before_copying() {
        assert!(copy_bytes(
            std::ptr::null(),
            MAX_CREDENTIAL_ID_BYTES + 1,
            "credential ID",
            ExpectedLength::Inclusive {
                minimum: 1,
                maximum: MAX_CREDENTIAL_ID_BYTES,
            },
        )
        .is_err());
        assert!(copy_bytes(
            std::ptr::null(),
            PRF_OUTPUT_BYTES - 1,
            "PRF output",
            ExpectedLength::Exact(PRF_OUTPUT_BYTES),
        )
        .is_err());
        assert!(copy_error(std::ptr::null(), MAX_ERROR_BYTES + 1).contains("longer than"));
    }
}
