use std::env;

const USE_LINUX_PAM_ENV_VAR: &str = "USE_LINUX_PAM";
const USE_OPENPAM_ENV_VAR: &str = "USE_OPENPAM";

#[derive(Debug, Clone, Copy)]
enum PamImplementation {
    LinuxPAM,
    OpenPAM,
}

impl PamImplementation {
    fn resolve() -> Self {
        if cfg!(feature = "linux-pam") {
            Self::LinuxPAM
        } else if cfg!(feature = "openpam") {
            Self::OpenPAM
        } else {
            if let Ok(v) = env::var(USE_LINUX_PAM_ENV_VAR) {
                if v != "0" {
                    return Self::LinuxPAM;
                }
            }

            if let Ok(v) = env::var(USE_OPENPAM_ENV_VAR) {
                if v != "0" {
                    return Self::OpenPAM;
                }
            }

            println!(
                "cargo:warning=No explicit PAM implementation given. Attempting to detect implementation."
            );

            let libpath = env::var("PAM_PATH").unwrap_or("libpam.so".to_string());

            let implementation = {
                match unsafe { libloading::os::unix::Library::new(&libpath) } {
                    Ok(library) => {
                        let is_openpam =
                            unsafe { library.get::<unsafe extern "C" fn()>(b"openpam_ttyconv") }
                                .is_ok();

                        let implementation = if is_openpam {
                            Self::OpenPAM
                        } else {
                            Self::LinuxPAM
                        };

                        println!(
                            "cargo:warning=Detected implementation: `{}`.",
                            implementation.display_str()
                        );

                        implementation
                    }
                    Err(err) => {
                        println!(
                            "cargo:warning=Failed to infer the PAM implementation in `{}`. Reason: `{}`",
                            libpath, err
                        );
                        Self::LinuxPAM
                    }
                }
            };

            println!(
                "cargo:warning=Assuming implementation: `{}`",
                implementation.display_str()
            );

            implementation
        }
    }

    fn impl_name(self) -> &'static str {
        match self {
            Self::LinuxPAM => "linux-pam",
            Self::OpenPAM => "openpam",
        }
    }

    fn set_feature(self) {
        let impl_name = self.impl_name();
        println!("cargo:rustc-cfg=pam_impl=\"{impl_name}\"");
    }

    fn display_str(self) -> &'static str {
        match self {
            Self::LinuxPAM => "Linux-PAM",
            Self::OpenPAM => "OpenPAM",
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed={}", USE_LINUX_PAM_ENV_VAR);
    println!("cargo:rerun-if-env-changed={}", USE_OPENPAM_ENV_VAR);
    println!("cargo:rerun-if-env-changed=PAM_PATH");

    if let Ok(pam_path) = env::var("PAM_PATH") {
        println!("cargo:rustc-link-lib={pam_path}");
    } else {
        pkg_config::probe_library("pam").expect("Failed to find libpam.so");
    }

    // Attempt to resolve with implementation is wanted by the user, and set it as the `pam-impl`
    // for the rustc cfg
    PamImplementation::resolve().set_feature();
}
