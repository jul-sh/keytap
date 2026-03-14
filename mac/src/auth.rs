use std::cell::{Cell, RefCell};
use std::io::Write;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, AllocAnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSApplicationDelegate, NSBackingStoreType, NSWindow, NSWindowStyleMask};
use objc2_authentication_services::*;
use objc2_foundation::*;

use crate::credential;
use crate::{Command, KeyOptions, OutputFormat, RegisterOptions};

// ---------- ivar storage ----------

pub struct AuthDelegateIvars {
    command: RefCell<Option<Command>>,
    anchor_window: RefCell<Option<Retained<NSWindow>>>,
    is_retry: Cell<bool>,
    // Keep the controller alive for the duration of the request.
    active_controller: RefCell<Option<Retained<ASAuthorizationController>>>,
}

// ---------- class definition ----------

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AuthDelegate"]
    #[ivars = AuthDelegateIvars]
    pub struct AuthDelegate;

    unsafe impl NSObjectProtocol for AuthDelegate {}

    // --- NSApplicationDelegate ---
    unsafe impl NSApplicationDelegate for AuthDelegate {
        #[unsafe(method(applicationDidFinishLaunching:))]
        fn app_did_finish_launching(&self, _notification: &NSNotification) {
            let command = self.ivars().command.borrow().clone().unwrap();
            match command {
                Command::Register(opts) => self.perform_registration(&opts),
                Command::Derive(opts) => self.perform_assertion(&opts, false),
                Command::PublicKey(opts) => self.perform_assertion(&opts, true),
            }
        }
    }

    // --- ASAuthorizationControllerDelegate ---
    unsafe impl ASAuthorizationControllerDelegate for AuthDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn authorization_controller_did_complete(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            self.handle_authorization(authorization);
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        fn authorization_controller_did_fail(
            &self,
            _controller: &ASAuthorizationController,
            error: &NSError,
        ) {
            self.handle_error(error);
        }
    }

    // ASAuthorizationControllerPresentationContextProviding
    // We implement this manually because define_class! doesn't yet support
    // returning Retained<T> (method_family = none) from protocol methods.
    unsafe impl ASAuthorizationControllerPresentationContextProviding for AuthDelegate {
        #[unsafe(method(presentationAnchorForAuthorizationController:))]
        fn presentation_anchor(
            &self,
            _controller: &ASAuthorizationController,
        ) -> *mut NSObject {
            let window = self.ivars().anchor_window.borrow().clone().unwrap();
            Retained::autorelease_return(Retained::into_super(Retained::into_super(window)))
        }
    }
);

// ---------- public constructor ----------

impl AuthDelegate {
    pub fn new(mtm: MainThreadMarker, command: Command) -> Retained<Self> {
        let this = mtm.alloc::<Self>();
        let this = this.set_ivars(AuthDelegateIvars {
            command: RefCell::new(Some(command)),
            anchor_window: RefCell::new(None),
            is_retry: Cell::new(false),
            active_controller: RefCell::new(None),
        });
        let this: Retained<Self> = unsafe { objc2::msg_send![super(this), init] };
        // Create anchor window.
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc::<NSWindow>(),
                NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1.0, 1.0)),
                NSWindowStyleMask::empty(),
                NSBackingStoreType::Buffered,
                true,
            )
        };
        *this.ivars().anchor_window.borrow_mut() = Some(window);
        this
    }
}

// ---------- registration ----------

impl AuthDelegate {
    fn perform_registration(&self, opts: &RegisterOptions) {
        if credential::load_credential().is_some() && !opts.replace_existing {
            eprintln!("error: a tapkey passkey is already registered on this Mac");
            eprintln!("  Run 'tapkey derive' to use it.");
            eprintln!(
                "  Use 'tapkey register --replace' only if you intend to rotate every derived key."
            );
            std::process::exit(1);
        }

        let rp_id = NSString::from_str("tapkey.jul.sh");
        let provider = unsafe {
            ASAuthorizationPlatformPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(
                ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
                &rp_id,
            )
        };

        let challenge = random_challenge();
        let name = NSString::from_str("tapkey");
        let user_id = NSData::with_bytes(b"tapkey-user");
        let request = unsafe {
            provider.createCredentialRegistrationRequestWithChallenge_name_userID(
                &challenge, &name, &user_id,
            )
        };

        // Set PRF to check for support.
        let prf_input =
            unsafe { ASAuthorizationPublicKeyCredentialPRFRegistrationInput::checkForSupport() };
        unsafe { request.setPrf(Some(&prf_input)) };

        let request: Retained<ASAuthorizationRequest> = Retained::into_super(request);
        self.run_controller(&NSArray::from_retained_slice(&[request]));
    }

    fn handle_registration(&self, authorization: &ASAuthorization) {
        let credential = unsafe { authorization.credential() };
        // Downcast from ProtocolObject<dyn ASAuthorizationCredential> to concrete type.
        let any: &AnyObject = ProtocolObject::as_ref(&*credential);
        let credential: &ASAuthorizationPlatformPublicKeyCredentialRegistration = any
            .downcast_ref()
            .expect("unexpected credential type");

        // Verify PRF support.
        let prf_output = unsafe { credential.prf() };
        match prf_output {
            Some(prf) if unsafe { prf.isSupported() } => {}
            _ => {
                eprintln!(
                    "error: passkey created but PRF is not supported by this authenticator"
                );
                eprintln!("  Platform passkeys on macOS 15+ should support PRF.");
                eprintln!("  Hardware security keys may not support the PRF extension.");
                std::process::exit(1);
            }
        }

        let cred_id = unsafe { credential.credentialID() };
        if let Err(e) = credential::save_credential(&cred_id.to_vec()) {
            eprintln!("error: failed to save credential: {e}");
            std::process::exit(1);
        }

        eprintln!("Passkey registered successfully.");
        eprintln!(
            "Credential saved to {}",
            credential::credential_path_display()
        );
        std::process::exit(0);
    }
}

// ---------- assertion (derive / public-key) ----------

impl AuthDelegate {
    fn perform_assertion(&self, opts: &KeyOptions, _is_public_key: bool) {
        let rp_id = NSString::from_str("tapkey.jul.sh");
        let provider = unsafe {
            ASAuthorizationPlatformPublicKeyCredentialProvider::initWithRelyingPartyIdentifier(
                ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
                &rp_id,
            )
        };

        let challenge = random_challenge();
        let request =
            unsafe { provider.createCredentialAssertionRequestWithChallenge(&challenge) };

        // Set allowed credentials from stored credential (unless retrying).
        if !self.ivars().is_retry.get() {
            if let Some(stored) = credential::load_credential() {
                let cred_id_data = NSData::with_bytes(&stored.credential_id);
                let descriptor = unsafe {
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor::initWithCredentialID(
                        ASAuthorizationPlatformPublicKeyCredentialDescriptor::alloc(),
                        &cred_id_data,
                    )
                };
                let allowed = NSArray::from_retained_slice(&[descriptor]);
                unsafe { request.setAllowedCredentials(&allowed) };
            }
        }

        // Set PRF salt input.
        let salt = tapkey_core::prf_salt_for_name(&opts.name).expect("invalid key name");
        let salt_data = NSData::with_bytes(&salt);
        let input_values = unsafe {
            ASAuthorizationPublicKeyCredentialPRFAssertionInputValues::initWithSaltInput1_saltInput2(
                ASAuthorizationPublicKeyCredentialPRFAssertionInputValues::alloc(),
                &salt_data,
                None,
            )
        };
        let prf_input = unsafe {
            ASAuthorizationPublicKeyCredentialPRFAssertionInput::initWithInputValues_perCredentialInputValues(
                ASAuthorizationPublicKeyCredentialPRFAssertionInput::alloc(),
                Some(&input_values),
                None,
            )
        };
        unsafe { request.setPrf(Some(&prf_input)) };

        let request: Retained<ASAuthorizationRequest> = Retained::into_super(request);
        self.run_controller(&NSArray::from_retained_slice(&[request]));
    }

    fn handle_assertion(&self, authorization: &ASAuthorization) {
        let credential = unsafe { authorization.credential() };
        let any: &AnyObject = ProtocolObject::as_ref(&*credential);
        let credential: &ASAuthorizationPlatformPublicKeyCredentialAssertion = any
            .downcast_ref()
            .expect("unexpected credential type");

        let prf_output =
            unsafe { credential.prf() }.expect("error: PRF output not available");

        let prf_data = unsafe { prf_output.first() };
        let prf_bytes = prf_data.to_vec();

        // Cache credential ID.
        let cred_id = unsafe { credential.credentialID() };
        if let Err(e) = credential::cache_credential_id_if_needed(&cred_id.to_vec()) {
            eprintln!("error: failed to cache credential: {e}");
            std::process::exit(1);
        }

        let raw_key =
            tapkey_core::derive_raw_key(&prf_bytes).expect("PRF output wrong length");

        let command = self.ivars().command.borrow().clone().unwrap();
        match &command {
            Command::Derive(opts) => self.output_derived_key(&raw_key, opts),
            Command::PublicKey(opts) => self.output_public_key(&raw_key, opts),
            Command::Register(_) => unreachable!(),
        }

        std::process::exit(0);
    }

    fn output_derived_key(&self, raw_key: &[u8], opts: &KeyOptions) {
        match opts.format {
            OutputFormat::Raw => {
                std::io::stdout().write_all(raw_key).unwrap();
            }
            OutputFormat::Ssh => {
                let formatted = tapkey_core::format_private_key(
                    raw_key,
                    tapkey_core::PrivateKeyFormat::SshPrivateKey,
                )
                .unwrap();
                print!("{}", String::from_utf8(formatted).unwrap());
            }
            _ => {
                let fmt = match opts.format {
                    OutputFormat::Hex => tapkey_core::PrivateKeyFormat::Hex,
                    OutputFormat::Base64 => tapkey_core::PrivateKeyFormat::Base64,
                    OutputFormat::Age => tapkey_core::PrivateKeyFormat::AgeSecretKey,
                    _ => unreachable!(),
                };
                let formatted = tapkey_core::format_private_key(raw_key, fmt).unwrap();
                println!("{}", String::from_utf8(formatted).unwrap());
            }
        }
    }

    fn output_public_key(&self, raw_key: &[u8], opts: &KeyOptions) {
        if matches!(opts.format, OutputFormat::Raw) {
            eprintln!("error: --format raw is not supported for public-key");
            std::process::exit(1);
        }
        let fmt = match opts.format {
            OutputFormat::Hex => tapkey_core::PublicKeyFormat::Hex,
            OutputFormat::Base64 => tapkey_core::PublicKeyFormat::Base64,
            OutputFormat::Age => tapkey_core::PublicKeyFormat::AgeRecipient,
            OutputFormat::Ssh => tapkey_core::PublicKeyFormat::SshPublicKey,
            OutputFormat::Raw => unreachable!(),
        };
        let formatted = tapkey_core::format_public_key(raw_key, fmt).unwrap();
        println!("{formatted}");
    }
}

// ---------- dispatch + error handling ----------

impl AuthDelegate {
    fn handle_authorization(&self, authorization: &ASAuthorization) {
        let command = self.ivars().command.borrow().clone().unwrap();
        match &command {
            Command::Register(_) => self.handle_registration(authorization),
            Command::Derive(_) | Command::PublicKey(_) => self.handle_assertion(authorization),
        }
    }

    fn handle_error(&self, error: &NSError) {
        let command = self.ivars().command.borrow().clone().unwrap();
        let domain = error.domain();
        let code = error.code();

        let auth_domain: &NSString = unsafe { ASAuthorizationErrorDomain };
        let is_auth_error = *domain == *auth_domain;

        if is_auth_error {
            let error_code = ASAuthorizationError(code);
            if error_code == ASAuthorizationError::Canceled {
                match &command {
                    Command::Register(_) => eprintln!("Registration cancelled."),
                    _ => eprintln!("Authentication cancelled."),
                }
                std::process::exit(1);
            }

            if error_code == ASAuthorizationError::Failed {
                match &command {
                    Command::Register(_) => {
                        eprintln!("error: registration failed — ensure your passkey provider is available");
                    }
                    _ => {
                        eprintln!("error: authentication failed — biometric or passkey authentication may have failed");
                    }
                }
                std::process::exit(1);
            }

            if error_code == ASAuthorizationError::NotHandled {
                match &command {
                    Command::Register(_) => {
                        eprintln!(
                            "error: passkey registration was not handled by the system"
                        );
                        std::process::exit(1);
                    }
                    _ => {
                        if !self.ivars().is_retry.get() {
                            eprintln!("Stored credential was not available. Retrying with discoverable passkeys...");
                            self.ivars().is_retry.set(true);
                            let opts = match &command {
                                Command::Derive(o) => o.clone(),
                                Command::PublicKey(o) => o.clone(),
                                _ => unreachable!(),
                            };
                            let is_public_key = matches!(&command, Command::PublicKey(_));
                            self.perform_assertion(&opts, is_public_key);
                            return;
                        }
                        eprintln!("error: no passkey was available for tapkey");
                        eprintln!(
                            "  Run 'tapkey register' first to create a passkey."
                        );
                        std::process::exit(1);
                    }
                }
            }
        }

        let desc = error.localizedDescription();
        match &command {
            Command::Register(_) => eprintln!("error: registration failed: {desc}"),
            _ => eprintln!("error: authentication failed: {desc}"),
        }
        std::process::exit(1);
    }

    fn run_controller(&self, requests: &NSArray<ASAuthorizationRequest>) {
        let controller = unsafe {
            ASAuthorizationController::initWithAuthorizationRequests(
                ASAuthorizationController::alloc(),
                requests,
            )
        };
        let delegate_obj: &ProtocolObject<dyn ASAuthorizationControllerDelegate> =
            ProtocolObject::from_ref(self);
        unsafe { controller.setDelegate(Some(delegate_obj)) };
        let provider_obj: &ProtocolObject<
            dyn ASAuthorizationControllerPresentationContextProviding,
        > = ProtocolObject::from_ref(self);
        unsafe { controller.setPresentationContextProvider(Some(provider_obj)) };
        unsafe { controller.performRequests() };
        *self.ivars().active_controller.borrow_mut() = Some(controller);
    }
}

// ---------- helpers ----------

fn random_challenge() -> Retained<NSData> {
    let mut bytes = [0u8; 32];
    unsafe {
        getentropy(bytes.as_mut_ptr().cast(), bytes.len());
    }
    NSData::with_bytes(&bytes)
}

unsafe extern "C" {
    fn getentropy(buf: *mut std::ffi::c_void, len: usize) -> std::ffi::c_int;
}
