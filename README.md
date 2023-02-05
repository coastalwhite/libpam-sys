# libpam-sys

This is an FFI wrapper of the [Pluggable Authentication Modules_][pam] (PAM) API.
The wrapper supports both the [Linux-PAM][linux-pam] and [OpenPAM][openpam]
implementation that are present across many _Linux_, _BSD_ and _macOS_ systems. 

## Important links

- [Documentation][docs]
- [Crates.io][crates]
- [Pampoon][pampoon]: A safe wrapper of the application PAM functions

## What is PAM?

[PAM][pam] is short for _Pluggable Authentication Modules_. It provides the
verification of user credentials for most Unix systems. This includes _Linux_,
_macOS_ and most _BSD_ distributions. PAM allows system administrators to alter
the authentication configuration without recompiling all the applications that
utilize PAM. It also also for more complicated authentication schemes, which are
commonly used within larger organizations. This includes the use of smartcards
and one-time tokens.

## Usage

In most cases, this crate is too low-level. In which case, you are better off
using a safe abstraction around this crate. Examples include [Pampoon][pampoon]
and [pam][pam-crate].

By default, the crate will detect the implementation of PAM that is present on
your system. Usually, this is all that is needed.

You can use the bindings in the root module to create a implementation-agnostic
PAM application or [PAM Module][pam-module]. The bindings outside of the
implementation specific modules can be used for implementation-specific PAM
applications and PAM modules.

### Cross compilation

There are environment variables to change the shared library path and to change
the PAM implementation.

- `PAM_PATH=/path/to/libpam.so` sets the linked path for `libpam.so`. If not
  set, [`pkg-config`][pkgconfig] is used to find the shared library.
- `USE_LINUX_PAM=1` makes the build assume that the shared library is
  [Linux-PAM][linux-pam].
- `USE_OPENPAM=1` makes the build assume that the shared library is
  [OpenPAM][OpenPAM].

There are also 3 features that force the library to utilize the bindings for one
of the implementations and expose more specific bindings which are present in
their corresponding modules.

- `linux-pam` ensures that [Linux-PAM][linux-pam] is assumed as the
  implementation and exposes the [Linux-PAM][linux-pam] specific functions.
- `openpam` ensures that [OpenPAM][openpam] is assumed as the implementation and
  exposes the [OpenPAM][openpam] specific functions.
- `read_cooked_lines` is a subfeature of `openpam` which exposes even more
  functions of [OpenPAM][openpam].

In general, the priority is that cargo features take precedence of environment
variables, and environment variables take precedence over the inferred
implementation.

## Why use this over the existing [`pam-sys`][pam-sys]?

This crate was created to address some problems with the [`pam-sys`][pam-sys]
crate. There are three main issues in [`pam-sys`][pam-sys] at the time of
writing.

1. Lack of support for other implementations of [PAM][pam]
2. [`pam-sys`][pam-sys] is more than what a `-sys` is supposed to do.
3. No support for cross-compilation

The second point seems to be fixed in _alpha_ released for the 1.0 release.
However, the author seems to have moved on from the project (which is fine).
This is also why committing back to the repository also is not possible.

This crates solves all these problems.

## License

The project is made available under the MIT and APACHE license. See the
`LICENSE-MIT` and `LICENSE-APACHE` files, respectively, for more information.

## Contributions

Please report any bugs and possible improvements as an issue within this
repository. Pull requests are also welcome.

[pam]: https://en.wikipedia.org/wiki/Pluggable_authentication_module
[linux-pam]: https://en.wikipedia.org/wiki/Linux_PAM
[openpam]: https://en.wikipedia.org/wiki/OpenPAM
[docs]: https://docs.rs/libpam-sys/latest/libpam-sys/
[crates]: https://crates.io/crates/libpam-sys
[pampoon]: https://github.com/coastalwhite/pampoon
[pam-crate]: https://github.com/1wilkens/pam
[pam-module]: https://linux.die.net/man/3/pam
[pkgconfig]: https://crates.io/crates/pkg-config
[pam-sys]: https://github.com/1wilkens/pam-sys