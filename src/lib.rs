#![allow(non_camel_case_types)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(feature = "linux-pam", feature = "openpam"))]
compile_error!("Cannot support two implementations of PAM at the same time. Consider enabling only one of the root features of this crate.");

#[cfg(not(any(pam_impl = "linux-pam", pam_impl = "openpam")))]
compile_error!("No PAM implementation is specified.");

use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
pub struct pam_handle_t {
    // Structure should never actually be instantiated. Only the alignment is important
    dummy: *const u8,
}

#[repr(C)]
pub struct pam_conv {
    pub conv:
        extern "C" fn(c_int, *const *mut pam_message, *mut *mut pam_response, *mut c_void) -> c_int,
    pub app_dataptr: *mut c_void,
}

#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

// Application functions
extern "C" {
    pub fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const pam_conv,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;

    pub fn pam_end(pamh: *mut pam_handle_t, pam_status: c_int) -> c_int;

    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_setcred(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: c_int) -> c_int;

    pub fn pam_open_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    pub fn pam_close_session(pamh: *mut pam_handle_t, flags: c_int) -> c_int;

    pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
}

// General Functions
extern "C" {
    pub fn pam_strerror(pamh: *mut pam_handle_t, errnum: c_int) -> *const c_char;

    pub fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
    pub fn pam_get_item(pamh: *const pam_handle_t, item_type: c_int, item: *const *mut c_void);

    pub fn pam_getenv(pamh: *mut pam_handle_t, name: *const c_char) -> *const c_char;
    pub fn pam_putenv(pamh: *mut pam_handle_t, name_value: *const c_char) -> c_int;
    pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *const c_char;

    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *const *mut c_char,
        prompt: *const c_char,
    ) -> c_int;

    pub fn pam_get_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *const *mut c_void,
    ) -> c_int;
    pub fn pam_set_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<extern "C" fn(*mut pam_handle_t, *mut c_void, c_int)>,
    ) -> c_int;
}

// Module functions
extern "C" {
    pub fn pam_sm_acct_mgmt(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
    pub fn pam_sm_authenticate(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
    pub fn pam_sm_chauthtok(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
    pub fn pam_sm_open_session(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
    pub fn pam_sm_close_session(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
    pub fn pam_sm_setcred(
        pamh: *mut pam_handle_t,
        flags: c_int,
        argc: c_int,
        argv: *const *mut c_char,
    ) -> c_int;
}

macro_rules! reexport_based_on_features {
    (
     $(
        $(#[$($attrss:tt)*])*
        $name:ident
     ),* $(,)?
    ) => {
        $(
            $(#[$($attrss)*])*
            ///
            /// This constant has a value dependent whether the Linux-PAM or OpenPAM was enabled.
            pub const $name: std::ffi::c_int = {
                if cfg!(pam_impl = "linux-pam") {
                    $crate::linux_pam::$name
                } else if cfg!(pam_impl = "openpam") {
                    $crate::openpam::$name
                } else {
                    0
                }

            };
        )*
    };
}

reexport_based_on_features! {
    // XSSO 5.2 PAM Status Codes

    /// Successful function return
    PAM_SUCCESS,

    /// dlopen() failure when dynamically loading a service module
    PAM_OPEN_ERR,

    /// Symbol not found
    PAM_SYMBOL_ERR,

    /// Error in service module
    PAM_SERVICE_ERR,

    /// System error
    PAM_SYSTEM_ERR,

    /// Memory buffer error
    PAM_BUF_ERR,

    /// The caller does not possess the required authority
    PAM_PERM_DENIED,

    /// Authentication failure
    PAM_AUTH_ERR,

    /// Cannot access authentication database because credentials supplied are insufficient
    PAM_CRED_INSUFFICIENT,

    /// Cannot retrieve authentication information
    PAM_AUTHINFO_UNAVAIL,

    /// The user is not known to the underlying account management module
    PAM_USER_UNKNOWN,

    /// An authentication service has maintained a retry count which has been reached.  No further
    /// retries should be attempted
    PAM_MAXTRIES,

    /// New authentication token required. This is normally returned if the machine security policies
    /// require that the password should be changed because the password is NULL or it has aged
    PAM_NEW_AUTHTOK_REQD,

    /// User account has expired
    PAM_ACCT_EXPIRED,

    /// Can not make/remove an entry for the specified session
    PAM_SESSION_ERR,

    /// Underlying authentication service can not retrieve user credentials unavailable
    PAM_CRED_UNAVAIL,

    /// User credentials expired
    PAM_CRED_EXPIRED,

    /// Failure setting user credentials
    PAM_CRED_ERR,

    /// No module specific data is present
    PAM_NO_MODULE_DATA,

    /// Conversation error
    PAM_CONV_ERR,

    /// Authentication token manipulation error
    PAM_AUTHTOK_ERR,

    /// Authentication information cannot be recovered
    PAM_AUTHTOK_RECOVERY_ERR,

    /// Authentication token lock busy
    PAM_AUTHTOK_LOCK_BUSY,

    /// Authentication token aging disabled
    PAM_AUTHTOK_DISABLE_AGING,

    /// Unable to complete operation. Try again
    PAM_TRY_AGAIN,

    /// Ignore underlying account module regardless of whether the control flag is required,
    /// optional, or sufficient
    PAM_IGNORE,

    /// General PAM failure
    PAM_ABORT,

    /// user's authentication token has expired
    PAM_AUTHTOK_EXPIRED,

    /// Module type unknown
    PAM_MODULE_UNKNOWN,

    /// Bad item passed to pam_*_item()
    PAM_BAD_ITEM,

    // XSSO 5.3 Constants

    /// Echo off when getting a response from a conversation
    PAM_PROMPT_ECHO_OFF,

    /// Echo on when getting a response from a conversation
    PAM_PROMPT_ECHO_ON,

    /// An error message
    PAM_ERROR_MSG,

    /// Textual information
    PAM_TEXT_INFO,

    /// The maximum number of messages passed through the conversation function call to the
    /// application
    PAM_MAX_NUM_MSG,

    /// The maximum number of bytes that can be passed by a message
    PAM_MAX_MSG_SIZE,

    /// The maximum number of bytes that can be passed by a response
    PAM_MAX_RESP_SIZE,

    // XSSO 5.4 Flags

    /// Authentication service should not generate any messages
    PAM_SILENT,

    /// The authentication service should return PAM_AUTH_ERROR if the user has a null
    /// authentication token
    PAM_DISALLOW_NULL_AUTHTOK,

    /// Set user credentials for an authentication service
    PAM_ESTABLISH_CRED,

    /// Delete user credentials associated with an authentication service
    PAM_DELETE_CRED,

    /// Reinitialize user credentials
    PAM_REINITIALIZE_CRED,

    /// Extend lifetime of user credentials
    PAM_REFRESH_CRED,

    /// The password service should only update those passwords that have aged.  If this flag is not
    /// passed, the password service should update all passwords.
    PAM_CHANGE_EXPIRED_AUTHTOK,

    // XSSO 5.3 Item_type

    /// The service name
    PAM_SERVICE,

    /// The user name
    PAM_USER,

    /// The tty name
    PAM_TTY,

    /// The remote host name
    PAM_RHOST,

    /// The pam_conv structure
    PAM_CONV,

    /// The authentication token (password)
    PAM_AUTHTOK,

    /// The old authentication token
    PAM_OLDAUTHTOK,

    /// The remote user name
    PAM_RUSER,

    /// The prompt for getting a username
    PAM_USER_PROMPT,

}

pub mod linux_pam {
    use std::ffi::c_int;

    #[cfg(any(docsrs, feature = "linux-pam"))]
    use {
        super::{pam_conv, pam_handle_t},
        std::ffi::c_char,
    };

    #[cfg(any(docsrs, feature = "linux-pam"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "linux-pam")))]
    extern "C" {
        pub fn pam_start_confdir(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const pam_conv,
            conf_dir: *const c_char,
            pamh: *mut *mut pam_handle_t,
        ) -> c_int;
    }

    // XSSO 5.2 PAM Status Codes
    pub const PAM_SUCCESS: c_int = 0;
    pub const PAM_OPEN_ERR: c_int = 1;
    pub const PAM_SYMBOL_ERR: c_int = 2;
    pub const PAM_SERVICE_ERR: c_int = 3;
    pub const PAM_SYSTEM_ERR: c_int = 4;
    pub const PAM_BUF_ERR: c_int = 5;
    pub const PAM_PERM_DENIED: c_int = 6;
    pub const PAM_AUTH_ERR: c_int = 7;
    pub const PAM_CRED_INSUFFICIENT: c_int = 8;
    pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
    pub const PAM_USER_UNKNOWN: c_int = 10;
    pub const PAM_MAXTRIES: c_int = 11;
    pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
    pub const PAM_ACCT_EXPIRED: c_int = 13;
    pub const PAM_SESSION_ERR: c_int = 14;
    pub const PAM_CRED_UNAVAIL: c_int = 15;
    pub const PAM_CRED_EXPIRED: c_int = 16;
    pub const PAM_CRED_ERR: c_int = 17;
    pub const PAM_NO_MODULE_DATA: c_int = 18;
    pub const PAM_CONV_ERR: c_int = 19;
    pub const PAM_AUTHTOK_ERR: c_int = 20;
    pub const PAM_AUTHTOK_RECOVERY_ERR: c_int = 21;
    pub const PAM_AUTHTOK_LOCK_BUSY: c_int = 22;
    pub const PAM_AUTHTOK_DISABLE_AGING: c_int = 23;
    pub const PAM_TRY_AGAIN: c_int = 24;
    pub const PAM_IGNORE: c_int = 25;
    pub const PAM_ABORT: c_int = 26;
    pub const PAM_AUTHTOK_EXPIRED: c_int = 27;
    pub const PAM_MODULE_UNKNOWN: c_int = 28;

    pub const PAM_BAD_ITEM: c_int = 29;

    // *** Start Linux-PAM extensions
    /// conversation function is event driven and data is not available yet
    pub const PAM_CONV_AGAIN: c_int = 30;
    /// please call this function again to complete authentication stack. Before calling again,
    /// verify that conversation is completed
    pub const PAM_INCOMPLETE: c_int = 31;
    // *** End Linux-PAM extensions

    // XSSO 5.3 Constants
    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_PROMPT_ECHO_ON: c_int = 2;
    pub const PAM_ERROR_MSG: c_int = 3;
    pub const PAM_TEXT_INFO: c_int = 4;

    pub const PAM_MAX_NUM_MSG: c_int = 32;
    pub const PAM_MAX_MSG_SIZE: c_int = 512;
    pub const PAM_MAX_RESP_SIZE: c_int = 512;

    // *** Start Linux-PAM extensions
    /// yes/no/maybe conditionals
    pub const PAM_RADIO_TYPE: c_int = 5;

    /// This is for server client non-human interaction.. these are NOT part of the X/Open PAM
    /// specification.
    pub const PAM_BINARY_PROMPT: c_int = 7;
    // *** End Linux-PAM extensions

    // XSSO 5.4 Flags
    // General Flags
    pub const PAM_SILENT: c_int = 0x8000;

    // These flags are used by pam_authenticate{,_secondary}()
    pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;

    // These flags are used for pam_setcred()
    pub const PAM_ESTABLISH_CRED: c_int = 0x2;
    pub const PAM_DELETE_CRED: c_int = 0x4;
    pub const PAM_REINITIALIZE_CRED: c_int = 0x8;
    pub const PAM_REFRESH_CRED: c_int = 0x10;

    // These flags are used by pam_chauthtok
    pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x20;

    // XSSO 5.5 Item_type
    pub const PAM_SERVICE: c_int = 1;
    pub const PAM_USER: c_int = 2;
    pub const PAM_TTY: c_int = 3;
    pub const PAM_RHOST: c_int = 4;
    pub const PAM_CONV: c_int = 5;
    pub const PAM_AUTHTOK: c_int = 6;
    pub const PAM_OLDAUTHTOK: c_int = 7;
    pub const PAM_RUSER: c_int = 8;
    pub const PAM_USER_PROMPT: c_int = 9;

    // *** Start Linux-PAM extensions
    /// app supplied function to override failure delays
    pub const PAM_FAIL_DELAY: c_int = 10;
    /// X display name
    pub const PAM_XDISPLAY: c_int = 11;
    /// X server authentication data
    pub const PAM_XAUTHDATA: c_int = 12;
    /// The type for pam_get_authtok
    pub const PAM_AUTHTOK_TYPE: c_int = 13;
    // *** End Linux-PAM extensions
}

pub mod openpam {
    use std::ffi::c_int;

    #[cfg(any(docsrs, feature = "openpam"))]
    use {
        super::{pam_conv, pam_handle_t},
        std::ffi::{c_char, c_void},
    };

    #[cfg(any(docsrs, feature = "openpam"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "openpam")))]
    extern "C" {
        pub fn openpam_borrow_cred(pamh: *mut pam_handle_t, pwd: *const passwd) -> c_int;

        pub fn openpam_subst(
            pamh: *const pam_handle_t,
            buf: *mut c_char,
            bufsize: usize,
            template: *const c_char,
        ) -> c_int;

        pub fn openpam_free_data(pamh: *mut pam_handle_t, data: *const c_void, status: c_int);

        pub fn openpam_free_envlist(envlist: *mut *mut c_char);

        pub fn openpam_get_option(pamh: *mut pam_handle_t, option: *const c_char) -> *const c_char;

        pub fn openpam_restore_cred(pamh: *mut pam_handle_t) -> c_int;

        pub fn openpam_set_option(
            pamh: *mut pam_handle_t,
            option: *const c_char,
            value: *const c_char,
        ) -> c_int;

        pub fn pam_error(pamh: *const pam_handle_t, fmt: *const c_char, ...) -> c_int;

        pub fn pam_get_authtok(
            pamh: *mut pam_handle_t,
            item: c_int,
            authtok: *const *mut c_char,
            prompt: *const c_char,
        ) -> c_int;

        pub fn pam_info(pamh: *const pam_handle_t, fmt: *const char, ...) -> c_int;

        pub fn pam_prompt(
            pamh: *const pam_handle_t,
            style: c_int,
            resp: *mut *mut c_char,
            fmt: *const char,
            ...
        ) -> c_int;

        pub fn pam_setenv(
            pamh: *mut pam_handle_t,
            name: *const c_char,
            value: *const c_char,
            overwrite: c_int,
        ) -> c_int;

        // TODO:
        // I am skipping these since I don't know what to do with the va_list. I know there is a
        // experimental features.
        //
        // int
        // pam_vinfo(const pam_handle_t *_pamh,
        //     const char *_fmt,
        //     va_list _ap)
        //     OPENPAM_FORMAT ((__printf__, 2, 0))
        //     OPENPAM_NONNULL((1,2));
        //
        // int
        // pam_verror(const pam_handle_t *_pamh,
        //     const char *_fmt,
        //     va_list _ap)
        //     OPENPAM_FORMAT ((__printf__, 2, 0))
        //     OPENPAM_NONNULL((1,2));
        //
        // int
        // pam_vprompt(const pam_handle_t *_pamh,
        //     int _style,
        //     char **_resp,
        //     const char *_fmt,
        //     va_list _ap)
        //     OPENPAM_FORMAT ((__printf__, 4, 0))
        //     OPENPAM_NONNULL((1,4));

        pub fn openpam_straddch(
            str: *mut *mut c_char,
            sizep: *mut usize,
            lenp: *mut usize,
            ch: c_int,
        ) -> c_int;

        pub fn openpam_set_feature(feature: c_int, onoff: c_int) -> c_int;
        pub fn openpam_get_feature(feature: c_int, onoff: *mut c_int) -> c_int;

        pub fn _openpam_log(level: c_int, func: *const c_char, fmt: *const c_char, ...);

        // Same here.
        //
        // #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
        // #define openpam_log(lvl, ...) \
        // 	_openpam_log((lvl), __func__, __VA_ARGS__)
        // #elif defined(__GNUC__) && (__GNUC__ >= 3)
        // #define openpam_log(lvl, ...) \
        // 	_openpam_log((lvl), __func__, __VA_ARGS__)
        // #elif defined(__GNUC__) && (__GNUC__ >= 2) && (__GNUC_MINOR__ >= 95)
        // #define openpam_log(lvl, fmt...) \
        // 	_openpam_log((lvl), __func__, ##fmt)
        // #elif defined(__GNUC__) && defined(__FUNCTION__)
        // #define openpam_log(lvl, fmt...) \
        // 	_openpam_log((lvl), __FUNCTION__, ##fmt)
        // #else
        // void
        // openpam_log(int _level,
        // 	const char *_format,
        // 	...)
        // 	OPENPAM_FORMAT ((__printf__, 2, 3))
        // 	OPENPAM_NONNULL((2));
        // #endif

        pub fn openpam_ttyconv(
            n: c_int,
            msg: *const *mut pam_message,
            resp: *mut *mut pam_response,
            data: *mut c_void,
        ) -> c_int;

        pub static openpam_ttyconv_timeout: c_int;

        pub fn openpam_nullconv(
            n: c_int,
            msg: *const *mut pam_message,
            resp: *mut *mut pam_response,
            data: *mut c_void,
        ) -> c_int;
    }

    #[cfg(any(docsrs, feature = "openpam"))]
    mod consts {
        use std::ffi::c_int;

        pub const OPENPAM_RESTRICT_SERVICE_NAME: c_int = 0;
        pub const OPENPAM_VERIFY_POLICY_FILE: c_int = 1;
        pub const OPENPAM_RESTRICT_MODULE_NAME: c_int = 2;
        pub const OPENPAM_VERIFY_MODULE_FILE: c_int = 3;
        pub const OPENPAM_FALLBACK_TO_OTHER: c_int = 4;
        pub const OPENPAM_NUM_FEATURES: c_int = 5;

        // Log to syslog
        pub const PAM_LOG_LIBDEBUG: c_int = -1;
        pub const PAM_LOG_DEBUG: c_int = 0;
        pub const PAM_LOG_VERBOSE: c_int = 1;
        pub const PAM_LOG_NOTICE: c_int = 2;
        pub const PAM_LOG_ERROR: c_int = 3;

        pub struct pam_message;
        pub struct pam_response;
        pub struct passwd;
    }

    #[cfg(any(docsrs, feature = "openpam"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "openpam")))]
    pub use consts::*;

    #[cfg(any(docsrs, feature = "read_cooked_lines"))]
    use libc::FILE;

    #[cfg(any(docsrs, feature = "read_cooked_lines"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "read_cooked_lines")))]
    extern "C" {
        pub fn openpam_readline(
            f: *mut FILE,
            lineno: *mut c_int,
            lenp: *mut usize,
        ) -> *mut c_char;

        pub fn openpam_readlinev(
            f: *mut FILE,
            lineno: *mut c_int,
            lenp: *mut c_int,
        ) -> *mut *mut c_char;

        pub fn openpam_readword(
            f: *mut FILE,
            lineno: *mut c_int,
            lenp: *mut usize,
        ) -> *mut c_char;
    }

    // XSSO 5.2 PAM Status Codes
    pub const PAM_SUCCESS: c_int = 0;
    pub const PAM_OPEN_ERR: c_int = 1;
    pub const PAM_SYMBOL_ERR: c_int = 2;
    pub const PAM_SERVICE_ERR: c_int = 3;
    pub const PAM_SYSTEM_ERR: c_int = 4;
    pub const PAM_BUF_ERR: c_int = 5;
    pub const PAM_CONV_ERR: c_int = 6;
    pub const PAM_PERM_DENIED: c_int = 7;
    pub const PAM_MAXTRIES: c_int = 8;
    pub const PAM_AUTH_ERR: c_int = 9;
    pub const PAM_NEW_AUTHTOK_REQD: c_int = 10;
    pub const PAM_CRED_INSUFFICIENT: c_int = 11;
    pub const PAM_AUTHINFO_UNAVAIL: c_int = 12;
    pub const PAM_USER_UNKNOWN: c_int = 13;
    pub const PAM_CRED_UNAVAIL: c_int = 14;
    pub const PAM_CRED_EXPIRED: c_int = 15;
    pub const PAM_CRED_ERR: c_int = 16;
    pub const PAM_ACCT_EXPIRED: c_int = 17;
    pub const PAM_AUTHTOK_EXPIRED: c_int = 18;
    pub const PAM_SESSION_ERR: c_int = 19;
    pub const PAM_AUTHTOK_ERR: c_int = 20;
    pub const PAM_AUTHTOK_RECOVERY_ERR: c_int = 21;
    pub const PAM_AUTHTOK_LOCK_BUSY: c_int = 22;
    pub const PAM_AUTHTOK_DISABLE_AGING: c_int = 23;
    pub const PAM_NO_MODULE_DATA: c_int = 24;
    pub const PAM_IGNORE: c_int = 25;
    pub const PAM_ABORT: c_int = 26;
    pub const PAM_TRY_AGAIN: c_int = 27;
    pub const PAM_MODULE_UNKNOWN: c_int = 28;

    // PAM_DOMAIN_UNKNOWN is specific in the XSSO but not used by Linux-PAM.
    /// Domain unknown
    pub const PAM_DOMAIN_UNKNOWN: c_int = 29;

    // *** Start OpenPAM extension
    pub const PAM_BAD_HANDLE: c_int = 30;
    pub const PAM_BAD_ITEM: c_int = 31;
    pub const PAM_BAD_FEATURE: c_int = 32;
    pub const PAM_BAD_CONSTANT: c_int = 33;
    pub const PAM_NUM_ERRORS: c_int = 33;
    // *** End OpenPAM extension

    // XSSO 5.3 Constants
    pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
    pub const PAM_PROMPT_ECHO_ON: c_int = 2;
    pub const PAM_ERROR_MSG: c_int = 3;
    pub const PAM_TEXT_INFO: c_int = 4;
    pub const PAM_MAX_NUM_MSG: c_int = 32;
    pub const PAM_MAX_MSG_SIZE: c_int = 512;
    pub const PAM_MAX_RESP_SIZE: c_int = 512;

    // XSSO 5.4 Flags
    // General Flags
    pub const PAM_SILENT: c_int = 0x7999_9999 + 1;

    // Flags for pam_authenticate
    pub const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;

    // Flags for pam_setcred
    pub const PAM_ESTABLISH_CRED: c_int = 0x1;
    pub const PAM_DELETE_CRED: c_int = 0x2;
    pub const PAM_REINITIALIZE_CRED: c_int = 0x4;
    pub const PAM_REFRESH_CRED: c_int = 0x8;

    // Flags for pam_sm_chauthtok
    pub const PAM_PRELIM_CHECK: c_int = 0x1;
    pub const PAM_UPDATE_AUTHTOK: c_int = 0x2;

    // Flags for pam_sm_chauthtok and pam_chauthtok
    pub const PAM_CHANGE_EXPIRED_AUTHTOK: c_int = 0x4;

    // XSSO 5.5 Item_type
    pub const PAM_SERVICE: c_int = 1;
    pub const PAM_USER: c_int = 2;
    pub const PAM_TTY: c_int = 3;
    pub const PAM_RHOST: c_int = 4;
    pub const PAM_CONV: c_int = 5;
    pub const PAM_AUTHTOK: c_int = 6;
    pub const PAM_OLDAUTHTOK: c_int = 7;
    pub const PAM_RUSER: c_int = 8;
    pub const PAM_USER_PROMPT: c_int = 9;

    // *** Start OpenPAM extension
    pub const PAM_REPOSITORY: c_int = 10;
    pub const PAM_AUTHTOK_PROMPT: c_int = 11;
    pub const PAM_OLDAUTHTOK_PROMPT: c_int = 12;
    pub const PAM_HOST: c_int = 13;
    pub const PAM_NUM_ITEMS: c_int = 14;
    // End OpenPAM extension
}
