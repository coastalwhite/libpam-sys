use core::slice;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{stdin, stdout, Write};

use libpam_sys::{
    pam_authenticate, pam_conv, pam_end, pam_handle_t, pam_message, pam_response, pam_start, pam_strerror, PAM_SUCCESS,
};

extern "C" fn conversation(
    num_msg: c_int,
    msg: *const *mut pam_message,
    resp: *mut *mut pam_response,
    _appdata_ptr: *mut c_void,
) -> c_int {
    let num_msg = usize::try_from(num_msg).unwrap();
    let msg = unsafe { slice::from_raw_parts(msg, num_msg) };
    let mut responses = Vec::with_capacity(num_msg);

    for i in 0..num_msg {
        let mut line = String::new();

        let msg_content = unsafe { msg[i].as_mut() }.unwrap().msg;
        let msg_content = unsafe { CStr::from_ptr(msg_content) };

        print!("{}", msg_content.to_str().unwrap());
        stdout().flush().unwrap();

        stdin().read_line(&mut line).unwrap();

        line.pop();
        line.push('\0');

        let resp = line.as_ptr() as *mut c_char;
        Box::leak(line.into_boxed_str());

        let response = pam_response {
            resp,
            resp_retcode: 0,
        };

        responses.push(response);
    }

    unsafe { *resp = responses.leak().as_ptr() as *mut pam_response };

    return PAM_SUCCESS;
}

pub fn get_error(pamh: *mut pam_handle_t, errnum: c_int) -> &'static str {
    let err_string = unsafe { pam_strerror(pamh, errnum) };
    let err_string = unsafe { CStr::from_ptr(err_string) };
    err_string.to_str().unwrap()
}

fn main() {
    let mut handler: pam_handle_t = unsafe { core::mem::zeroed() };
    let mut pamh = &mut handler as *mut pam_handle_t;
    
    let pam_conversation = pam_conv {
        conv: conversation,
        app_dataptr: core::ptr::null::<c_void>() as *mut c_void,
    };

    let mut service_name = String::from("pam_example");
    service_name.push('\0');
    let service_name = service_name.as_ptr() as *const c_char;
    let user = core::ptr::null();

    let retval = unsafe {
        pam_start(
            service_name,
            user,
            &pam_conversation as *const pam_conv,
            &mut pamh as *mut *mut pam_handle_t,
        )
    };

    if retval != PAM_SUCCESS {
        println!("{}", get_error(pamh, retval));
    }

    let retval = unsafe { pam_authenticate(pamh, 0) };

    if retval != PAM_SUCCESS {
        println!("{}", get_error(pamh, retval));
    }

    let retval = unsafe { pam_end(pamh, 0) };

    if retval != PAM_SUCCESS {
        println!("{}", get_error(pamh, retval));
    }
}
