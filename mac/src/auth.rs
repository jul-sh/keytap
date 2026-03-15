pub enum RegistrationOutcome {
    Success { credential_id: Vec<u8> },
    Error(String),
}

pub enum AssertionOutcome {
    Success {
        credential_id: Vec<u8>,
        prf_output: Vec<u8>,
    },
    Error(String),
}

type RawCallback = unsafe extern "C" fn(
    context: u64,
    status: i32,
    data: *const u8,
    data_len: usize,
    extra: *const u8,
    extra_len: usize,
);

extern "C" {
    fn tapkey_register(context: u64, callback: RawCallback);
    fn tapkey_assert(
        salt_ptr: *const u8,
        salt_len: usize,
        cred_id_ptr: *const u8,
        cred_id_len: usize,
        context: u64,
        callback: RawCallback,
    );
}

unsafe extern "C" fn on_registration(
    context: u64,
    status: i32,
    data: *const u8,
    data_len: usize,
    _extra: *const u8,
    _extra_len: usize,
) {
    let cb = unsafe { Box::from_raw(context as *mut Box<dyn Fn(RegistrationOutcome)>) };
    if status != 0 {
        let msg = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(data, data_len)) };
        cb(RegistrationOutcome::Error(msg.to_string()));
    } else {
        let cred_id = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
        cb(RegistrationOutcome::Success { credential_id: cred_id });
    }
}

unsafe extern "C" fn on_assertion(
    context: u64,
    status: i32,
    data: *const u8,
    data_len: usize,
    extra: *const u8,
    extra_len: usize,
) {
    let cb = unsafe { Box::from_raw(context as *mut Box<dyn Fn(AssertionOutcome)>) };
    if status != 0 {
        let msg = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(data, data_len)) };
        cb(AssertionOutcome::Error(msg.to_string()));
    } else {
        let cred_id = unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec();
        let prf = unsafe { std::slice::from_raw_parts(extra, extra_len) }.to_vec();
        cb(AssertionOutcome::Success {
            credential_id: cred_id,
            prf_output: prf,
        });
    }
}

pub fn start_registration(callback: Box<dyn Fn(RegistrationOutcome)>) {
    let ctx = Box::into_raw(Box::new(callback)) as u64;
    unsafe { tapkey_register(ctx, on_registration) };
}

pub fn start_assertion(
    key_name: &str,
    preferred_credential_id: Option<&[u8]>,
    callback: Box<dyn Fn(AssertionOutcome)>,
) {
    let prf_salt = tapkey_core::prf_salt_for_name(key_name).expect("invalid key name");
    let (cred_ptr, cred_len) = match preferred_credential_id {
        Some(id) => (id.as_ptr(), id.len()),
        None => (std::ptr::null(), 0),
    };
    let ctx = Box::into_raw(Box::new(callback)) as u64;
    unsafe {
        tapkey_assert(
            prf_salt.as_ptr(),
            prf_salt.len(),
            cred_ptr,
            cred_len,
            ctx,
            on_assertion,
        );
    }
}
