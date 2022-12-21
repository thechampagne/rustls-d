/*
 * Copyright 2022 XXIV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
module rustls;

enum rustls_result {
  OK = 7000,
  IO = 7001,
  NULL_PARAMETER = 7002,
  INVALID_DNS_NAME_ERROR = 7003,
  PANIC = 7004,
  CERTIFICATE_PARSE_ERROR = 7005,
  PRIVATE_KEY_PARSE_ERROR = 7006,
  INSUFFICIENT_SIZE = 7007,
  NOT_FOUND = 7008,
  INVALID_PARAMETER = 7009,
  UNEXPECTED_EOF = 7010,
  PLAINTEXT_EMPTY = 7011,
  CORRUPT_MESSAGE = 7100,
  NO_CERTIFICATES_PRESENTED = 7101,
  DECRYPT_ERROR = 7102,
  FAILED_TO_GET_CURRENT_TIME = 7103,
  FAILED_TO_GET_RANDOM_BYTES = 7113,
  HANDSHAKE_NOT_COMPLETE = 7104,
  PEER_SENT_OVERSIZED_RECORD = 7105,
  NO_APPLICATION_PROTOCOL = 7106,
  BAD_MAX_FRAGMENT_SIZE = 7114,
  UNSUPPORTED_NAME_TYPE = 7115,
  ENCRYPT_ERROR = 7116,
  CERT_INVALID_ENCODING = 7117,
  CERT_INVALID_SIGNATURE_TYPE = 7118,
  CERT_INVALID_SIGNATURE = 7119,
  CERT_INVALID_DATA = 7120,
  PEER_INCOMPATIBLE_ERROR = 7107,
  PEER_MISBEHAVED_ERROR = 7108,
  INAPPROPRIATE_MESSAGE = 7109,
  INAPPROPRIATE_HANDSHAKE_MESSAGE = 7110,
  CORRUPT_MESSAGE_PAYLOAD = 7111,
  GENERAL = 7112,
  ALERT_CLOSE_NOTIFY = 7200,
  ALERT_UNEXPECTED_MESSAGE = 7201,
  ALERT_BAD_RECORD_MAC = 7202,
  ALERT_DECRYPTION_FAILED = 7203,
  ALERT_RECORD_OVERFLOW = 7204,
  ALERT_DECOMPRESSION_FAILURE = 7205,
  ALERT_HANDSHAKE_FAILURE = 7206,
  ALERT_NO_CERTIFICATE = 7207,
  ALERT_BAD_CERTIFICATE = 7208,
  ALERT_UNSUPPORTED_CERTIFICATE = 7209,
  ALERT_CERTIFICATE_REVOKED = 7210,
  ALERT_CERTIFICATE_EXPIRED = 7211,
  ALERT_CERTIFICATE_UNKNOWN = 7212,
  ALERT_ILLEGAL_PARAMETER = 7213,
  ALERT_UNKNOWN_CA = 7214,
  ALERT_ACCESS_DENIED = 7215,
  ALERT_DECODE_ERROR = 7216,
  ALERT_DECRYPT_ERROR = 7217,
  ALERT_EXPORT_RESTRICTION = 7218,
  ALERT_PROTOCOL_VERSION = 7219,
  ALERT_INSUFFICIENT_SECURITY = 7220,
  ALERT_INTERNAL_ERROR = 7221,
  ALERT_INAPPROPRIATE_FALLBACK = 7222,
  ALERT_USER_CANCELED = 7223,
  ALERT_NO_RENEGOTIATION = 7224,
  ALERT_MISSING_EXTENSION = 7225,
  ALERT_UNSUPPORTED_EXTENSION = 7226,
  ALERT_CERTIFICATE_UNOBTAINABLE = 7227,
  ALERT_UNRECOGNISED_NAME = 7228,
  ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 7229,
  ALERT_BAD_CERTIFICATE_HASH_VALUE = 7230,
  ALERT_UNKNOWN_PSK_IDENTITY = 7231,
  ALERT_CERTIFICATE_REQUIRED = 7232,
  ALERT_NO_APPLICATION_PROTOCOL = 7233,
  ALERT_UNKNOWN = 7234,
  CERT_SCT_MALFORMED = 7319,
  CERT_SCT_INVALID_SIGNATURE = 7320,
  CERT_SCT_TIMESTAMP_IN_FUTURE = 7321,
  CERT_SCT_UNSUPPORTED_VERSION = 7322,
  CERT_SCT_UNKNOWN_LOG = 7323,
}

/**
 * Definitions of known TLS protocol versions.
 */
enum rustls_tls_version {
  VERSION_SSLV2 = 512,
  VERSION_SSLV3 = 768,
  VERSION_TLSV1_0 = 769,
  VERSION_TLSV1_1 = 770,
  VERSION_TLSV1_2 = 771,
  VERSION_TLSV1_3 = 772,
}

/**
 * An X.509 certificate, as used in rustls.
 * Corresponds to `Certificate` in the Rust API.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.Certificate.html>
 */
struct rustls_certificate;

/**
 * The complete chain of certificates to send during a TLS handshake,
 * plus a private key that matches the end-entity (leaf) certificate.
 * Corresponds to `CertifiedKey` in the Rust API.
 * <https://docs.rs/rustls/0.20.0/rustls/sign/struct.CertifiedKey.html>
 */
struct rustls_certified_key;

/**
 * A verifier of client certificates that requires all certificates to be
 * trusted based on a given `rustls_root_cert_store`. Usable in building server
 * configurations. Connections without such a client certificate will not
 * be accepted.
 */
struct rustls_client_cert_verifier;

/**
 * Alternative to `rustls_client_cert_verifier` that allows connections
 * with or without a client certificate. If the client offers a certificate,
 * it will be verified (and rejected if it is not valid). If the client
 * does not offer a certificate, the connection will succeed.
 *
 * The application can retrieve the certificate, if any, with
 * rustls_connection_get_peer_certificate.
 */
struct rustls_client_cert_verifier_optional;

/**
 * A client config that is done being constructed and is now read-only.
 * Under the hood, this object corresponds to an `Arc<ClientConfig>`.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ClientConfig.html>
 */
struct rustls_client_config;

/**
 * A client config being constructed. A builder can be modified by,
 * e.g. rustls_client_config_builder_load_roots_from_file. Once you're
 * done configuring settings, call rustls_client_config_builder_build
 * to turn it into a *rustls_client_config. This object is not safe
 * for concurrent mutation. Under the hood, it corresponds to a
 * `Box<ClientConfig>`.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ConfigBuilder.html>
 */
struct rustls_client_config_builder;

struct rustls_connection;

/**
 * An alias for `struct iovec` from uio.h (on Unix) or `WSABUF` on Windows. You should cast
 * `const struct rustls_iovec *` to `const struct iovec *` on Unix, or `const *LPWSABUF`
 * on Windows. See [`std::io::IoSlice`] for details on interoperability with platform
 * specific vectored IO.
 */
struct rustls_iovec;

/**
 * A root certificate store.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.RootCertStore.html>
 */
struct rustls_root_cert_store;

/**
 * A server config that is done being constructed and is now read-only.
 * Under the hood, this object corresponds to an `Arc<ServerConfig>`.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ServerConfig.html>
 */
struct rustls_server_config;

/**
 * A server config being constructed. A builder can be modified by,
 * e.g. rustls_server_config_builder_load_native_roots. Once you're
 * done configuring settings, call rustls_server_config_builder_build
 * to turn it into a *const rustls_server_config. This object is not safe
 * for concurrent mutation.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ConfigBuilder.html>
 */
struct rustls_server_config_builder;

/**
 * A read-only view of a slice of Rust byte slices.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
 * provide access via a pointer to an opaque struct and an accessor method
 * that acts on that struct to get entries of type `rustls_slice_bytes`.
 * Internally, the pointee is a `&[&[u8]]`.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not call its methods beyond the
 * allowed lifetime.
 */
struct rustls_slice_slice_bytes;

/**
 * A read-only view of a slice of multiple Rust `&str`'s (that is, multiple
 * strings). Like `rustls_str`, this guarantees that each string contains
 * UTF-8 and no NUL bytes. Strings are not NUL-terminated.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
 * can't provide a straightforward `data` and `len` structure. Instead, we
 * provide access via a pointer to an opaque struct and accessor methods.
 * Internally, the pointee is a `&[&str]`.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not call its methods beyond the
 * allowed lifetime.
 */
struct rustls_slice_str;

/**
 * A cipher suite supported by rustls.
 */
struct rustls_supported_ciphersuite;

/**
 * A read-only view on a Rust `&str`. The contents are guaranteed to be valid
 * UTF-8. As an additional guarantee on top of Rust's normal UTF-8 guarantee,
 * a `rustls_str` is guaranteed not to contain internal NUL bytes, so it is
 * safe to interpolate into a C string or compare using strncmp. Keep in mind
 * that it is not NUL-terminated.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
struct rustls_str {
  const char *data;
  size_t len;
}

/**
 * A read-only view on a Rust byte slice.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes than can be safely read.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
struct rustls_slice_bytes {
  const ubyte *data;
  size_t len;
}

/**
 * User-provided input to a custom certificate verifier callback. See
 * rustls_client_config_builder_dangerous_set_certificate_verifier().
 */
alias rustls_verify_server_cert_user_data = void*;

/**
 * Input to a custom certificate verifier callback. See
 * rustls_client_config_builder_dangerous_set_certificate_verifier().
 */
struct rustls_verify_server_cert_params {
  rustls_slice_bytes end_entity_cert_der;
  const rustls_slice_slice_bytes *intermediate_certs_der;
  rustls_str dns_name;
  rustls_slice_bytes ocsp_response;
}

extern(C) alias rustls_verify_server_cert_callback = uint function(rustls_verify_server_cert_user_data userdata, const rustls_verify_server_cert_params *params);

alias rustls_log_level = size_t;

struct rustls_log_params {
  rustls_log_level level;
  rustls_str message;
}

extern(C) alias rustls_log_callback = void function(void *userdata, const rustls_log_params *params);

/**
 * A return value for a function that may return either success (0) or a
 * non-zero value representing an error. The values should match socket
 * error numbers for your operating system - for example, the integers for
 * ETIMEDOUT, EAGAIN, or similar.
 */
alias rustls_io_result = int;

/**
 * A callback for rustls_connection_read_tls.
 * An implementation of this callback should attempt to read up to n bytes from the
 * network, storing them in `buf`. If any bytes were stored, the implementation should
 * set out_n to the number of bytes stored and return 0. If there was an error,
 * the implementation should return a nonzero rustls_io_result, which will be
 * passed through to the caller. On POSIX systems, returning `errno` is convenient.
 * On other systems, any appropriate error code works.
 * It's best to make one read attempt to the network per call. Additional reads will
 * be triggered by subsequent calls to one of the `_read_tls` methods.
 * `userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
 * cases that should be a struct that contains, at a minimum, a file descriptor.
 * The buf and out_n pointers are borrowed and should not be retained across calls.
 */
extern(C) alias rustls_read_callback = rustls_io_result function(void *userdata, ubyte *buf, size_t n, size_t *out_n);

/**
 * A callback for rustls_connection_write_tls.
 * An implementation of this callback should attempt to write the `n` bytes in buf
 * to the network. If any bytes were written, the implementation should
 * set out_n to the number of bytes stored and return 0. If there was an error,
 * the implementation should return a nonzero rustls_io_result, which will be
 * passed through to the caller. On POSIX systems, returning `errno` is convenient.
 * On other systems, any appropriate error code works.
 * It's best to make one write attempt to the network per call. Additional writes will
 * be triggered by subsequent calls to rustls_connection_write_tls.
 * `userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
 * cases that should be a struct that contains, at a minimum, a file descriptor.
 * The buf and out_n pointers are borrowed and should not be retained across calls.
 */
extern(C) alias rustls_write_callback = rustls_io_result function(void *userdata, const ubyte *buf, size_t n, size_t *out_n);

/**
 * A callback for rustls_connection_write_tls_vectored.
 * An implementation of this callback should attempt to write the bytes in
 * the given `count` iovecs to the network. If any bytes were written,
 * the implementation should set out_n to the number of bytes written and return 0.
 * If there was an error, the implementation should return a nonzero rustls_io_result,
 * which will be passed through to the caller. On POSIX systems, returning `errno` is convenient.
 * On other systems, any appropriate error code works.
 * It's best to make one write attempt to the network per call. Additional write will
 * be triggered by subsequent calls to one of the `_write_tls` methods.
 * `userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
 * cases that should be a struct that contains, at a minimum, a file descriptor.
 * The buf and out_n pointers are borrowed and should not be retained across calls.
 */
extern(C) alias rustls_write_vectored_callback = rustls_io_result function(void *userdata, const rustls_iovec *iov, size_t count, size_t *out_n);

/**
 * Any context information the callback will receive when invoked.
 */
alias rustls_client_hello_userdata = void*;

/**
 * A read-only view on a Rust slice of 16-bit integers in platform endianness.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes than can be safely read.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
struct rustls_slice_u16 {
  const ushort *data;
  size_t len;
}

/**
 * The TLS Client Hello information provided to a ClientHelloCallback function.
 * `sni_name` is the SNI servername provided by the client. If the client
 * did not provide an SNI, the length of this `rustls_string` will be 0. The
 * signature_schemes carries the values supplied by the client or, should
 * the client not use this TLS extension, the default schemes in the rustls
 * library. See: <https://docs.rs/rustls/0.20.0/rustls/internal/msgs/enums/enum.SignatureScheme.html>.
 * `alpn` carries the list of ALPN protocol names that the client proposed to
 * the server. Again, the length of this list will be 0 if none were supplied.
 *
 * All this data, when passed to a callback function, is only accessible during
 * the call and may not be modified. Users of this API must copy any values that
 * they want to access when the callback returned.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 */
struct rustls_client_hello {
  rustls_str sni_name;
  rustls_slice_u16 signature_schemes;
  const rustls_slice_slice_bytes *alpn;
}

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config`. This callback will be invoked by a `rustls_connection`
 * once the TLS client hello message has been received.
 * `userdata` will be set based on rustls_connection_set_userdata.
 * `hello` gives the value of the available client announcements, as interpreted
 * by rustls. See the definition of `rustls_client_hello` for details.
 *
 * NOTE:
 * - the passed in `hello` and all its values are only available during the
 *   callback invocations.
 * - the passed callback function must be safe to call multiple times concurrently
 *   with the same userdata, unless there is only a single config and connection
 *   where it is installed.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 */
extern(C) alias rustls_client_hello_callback = const rustls_certified_key* function(rustls_client_hello_userdata userdata, const rustls_client_hello *hello);

/**
 * Any context information the callback will receive when invoked.
 */
alias rustls_session_store_userdata = void*;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`. This callback will be
 * invoked by a TLS session when looking up the data for a TLS session id.
 * `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
 *
 * The `buf` points to `count` consecutive bytes where the
 * callback is expected to copy the result to. The number of copied bytes
 * needs to be written to `out_n`. The callback should not read any
 * data from `buf`.
 *
 * If the value to copy is larger than `count`, the callback should never
 * do a partial copy but instead remove the value from its store and
 * act as if it was never found.
 *
 * The callback should return RUSTLS_RESULT_OK to indicate that a value was
 * retrieved and written in its entirety into `buf`, or RUSTLS_RESULT_NOT_FOUND
 * if no session was retrieved.
 *
 * When `remove_after` is != 0, the returned data needs to be removed
 * from the store.
 *
 * NOTE: the passed in `key` and `buf` are only available during the
 * callback invocation.
 * NOTE: callbacks used in several sessions via a common config
 * must be implemented thread-safe.
 */
extern(C) alias rustls_session_store_get_callback = uint function(rustls_session_store_userdata userdata, const rustls_slice_bytes *key, int remove_after, ubyte *buf, size_t count, size_t *out_n);

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`. This callback will be
 * invoked by a TLS session when a TLS session has been created and an id
 * for later use is handed to the client/has been received from the server.
 * `userdata` will be supplied based on rustls_{client,server}_session_set_userdata.
 *
 * The callback should return RUSTLS_RESULT_OK to indicate that a value was
 * successfully stored, or RUSTLS_RESULT_IO on failure.
 *
 * NOTE: the passed in `key` and `val` are only available during the
 * callback invocation.
 * NOTE: callbacks used in several sessions via a common config
 * must be implemented thread-safe.
 */
extern(C) alias rustls_session_store_put_callback = uint function(rustls_session_store_userdata userdata, const rustls_slice_bytes *key, const rustls_slice_bytes *val);

extern(C) const rustls_supported_ciphersuite[9] *RUSTLS_ALL_CIPHER_SUITES;

extern(C) const size_t RUSTLS_ALL_CIPHER_SUITES_LEN;

extern(C) const rustls_supported_ciphersuite[9] *RUSTLS_DEFAULT_CIPHER_SUITES;

extern(C) const size_t RUSTLS_DEFAULT_CIPHER_SUITES_LEN;

extern(C) const ushort[2] RUSTLS_ALL_VERSIONS;

extern(C) const size_t RUSTLS_ALL_VERSIONS_LEN;

extern(C) const ushort[2] RUSTLS_DEFAULT_VERSIONS;

extern(C) const size_t RUSTLS_DEFAULT_VERSIONS_LEN;

/**
 * Returns a static string containing the rustls-ffi version as well as the
 * rustls version. The string is alive for the lifetime of the program and does
 * not need to be freed.
 */
extern(C) rustls_str rustls_version();

/**
 * Get the DER data of the certificate itself.
 * The data is owned by the certificate and has the same lifetime.
 */
extern(C) rustls_result rustls_certificate_get_der(const rustls_certificate *cert,
                                         const ubyte **out_der_data,
                                         size_t *out_der_len);

/**
 * Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
 * <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
 * The bytes from the assignment are interpreted in network order.
 */
extern(C) ushort rustls_supported_ciphersuite_get_suite(const rustls_supported_ciphersuite *supported_ciphersuite);

/**
 * Returns the name of the ciphersuite as a `rustls_str`. If the provided
 * ciphersuite is invalid, the rustls_str will contain the empty string. The
 * lifetime of the `rustls_str` is the lifetime of the program, it does not
 * need to be freed.
 */
extern(C) rustls_str rustls_supported_ciphersuite_get_name(const rustls_supported_ciphersuite *supported_ciphersuite);

/**
 * Return the length of rustls' list of supported cipher suites.
 */
extern(C) size_t rustls_all_ciphersuites_len();

/**
 * Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
 * for i < rustls_all_ciphersuites_len().
 * The returned pointer is valid for the lifetime of the program and may be used directly when
 * building a ClientConfig or ServerConfig.
 */
extern(C) const(rustls_supported_ciphersuite)* rustls_all_ciphersuites_get_entry(size_t i);

/**
 * Return the length of rustls' list of default cipher suites.
 */
extern(C) size_t rustls_default_ciphersuites_len();

/**
 * Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
 * for i < rustls_default_ciphersuites_len().
 * The returned pointer is valid for the lifetime of the program and may be used directly when
 * building a ClientConfig or ServerConfig.
 */
extern(C) const(rustls_supported_ciphersuite)* rustls_default_ciphersuites_get_entry(size_t i);

/**
 * Build a `rustls_certified_key` from a certificate chain and a private key.
 * `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
 * a series of PEM-encoded certificates, with the end-entity (leaf)
 * certificate first.
 *
 * `private_key` must point to a buffer of `private_key_len` bytes, containing
 * a PEM-encoded private key in either PKCS#1 or PKCS#8 format.
 *
 * On success, this writes a pointer to the newly created
 * `rustls_certified_key` in `certified_key_out`. That pointer must later
 * be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
 * internally, this is an atomically reference-counted pointer, so even after
 * the original caller has called `rustls_certified_key_free`, other objects
 * may retain a pointer to the object. The memory will be freed when all
 * references are gone.
 *
 * This function does not take ownership of any of its input pointers. It
 * parses the pointed-to data and makes a copy of the result. You may
 * free the cert_chain and private_key pointers after calling it.
 *
 * Typically, you will build a `rustls_certified_key`, use it to create a
 * `rustls_server_config` (which increments the reference count), and then
 * immediately call `rustls_certified_key_free`. That leaves the
 * `rustls_server_config` in possession of the sole reference, so the
 * `rustls_certified_key`'s memory will automatically be released when
 * the `rustls_server_config` is freed.
 */
extern(C) rustls_result rustls_certified_key_build(const ubyte *cert_chain,
                                         size_t cert_chain_len,
                                         const ubyte *private_key,
                                         size_t private_key_len,
                                         const rustls_certified_key **certified_key_out);

/**
 * Return the i-th rustls_certificate in the rustls_certified_key. 0 gives the
 * end-entity certificate. 1 and higher give certificates from the chain.
 * Indexes higher than the last available certificate return NULL.
 *
 * The returned certificate is valid until the rustls_certified_key is freed.
 */
extern(C) const(rustls_certificate)* rustls_certified_key_get_certificate(const rustls_certified_key *certified_key,
                                                                      size_t i);

/**
 * Create a copy of the rustls_certified_key with the given OCSP response data
 * as DER encoded bytes. The OCSP response may be given as NULL to clear any
 * possibly present OCSP data from the cloned key.
 * The cloned key is independent from its original and needs to be freed
 * by the application.
 */
extern(C) rustls_result rustls_certified_key_clone_with_ocsp(const rustls_certified_key *certified_key,
                                                   const rustls_slice_bytes *ocsp_response,
                                                   const rustls_certified_key **cloned_key_out);

/**
 * "Free" a certified_key previously returned from
 * rustls_certified_key_build. Since certified_key is actually an
 * atomically reference-counted pointer, extant certified_key may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_certified_key_free(const rustls_certified_key *key);

/**
 * Create a rustls_root_cert_store. Caller owns the memory and must
 * eventually call rustls_root_cert_store_free. The store starts out empty.
 * Caller must add root certificates with rustls_root_cert_store_add_pem.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.RootCertStore.html#method.empty>
 */
extern(C) rustls_root_cert_store *rustls_root_cert_store_new();

/**
 * Add one or more certificates to the root cert store using PEM encoded data.
 *
 * When `strict` is true an error will return a `CertificateParseError`
 * result. So will an attempt to parse data that has zero certificates.
 *
 * When `strict` is false, unparseable root certificates will be ignored.
 * This may be useful on systems that have syntactically invalid root
 * certificates.
 */
extern(C) rustls_result rustls_root_cert_store_add_pem(rustls_root_cert_store *store,
                                             const ubyte *pem,
                                             size_t pem_len,
                                             bool strict);

/**
 * Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_root_cert_store_free(rustls_root_cert_store *store);

/**
 * Create a new client certificate verifier for the root store. The verifier
 * can be used in several rustls_server_config instances. Must be freed by
 * the application when no longer needed. See the documentation of
 * rustls_client_cert_verifier_free for details about lifetime.
 * This copies the contents of the rustls_root_cert_store. It does not take
 * ownership of the pointed-to memory.
 */
extern(C) const(rustls_client_cert_verifier)* rustls_client_cert_verifier_new(const rustls_root_cert_store *store);

/**
 * "Free" a verifier previously returned from
 * rustls_client_cert_verifier_new. Since rustls_client_cert_verifier is actually an
 * atomically reference-counted pointer, extant server_configs may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_client_cert_verifier_free(const rustls_client_cert_verifier *verifier);

/**
 * Create a new rustls_client_cert_verifier_optional for the root store. The
 * verifier can be used in several rustls_server_config instances. Must be
 * freed by the application when no longer needed. See the documentation of
 * rustls_client_cert_verifier_optional_free for details about lifetime.
 * This copies the contents of the rustls_root_cert_store. It does not take
 * ownership of the pointed-to data.
 */
extern(C) const(rustls_client_cert_verifier_optional)* rustls_client_cert_verifier_optional_new(const rustls_root_cert_store *store);

/**
 * "Free" a verifier previously returned from
 * rustls_client_cert_verifier_optional_new. Since rustls_client_cert_verifier_optional
 * is actually an atomically reference-counted pointer, extant server_configs may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_client_cert_verifier_optional_free(const rustls_client_cert_verifier_optional *verifier);

/**
 * Create a rustls_client_config_builder. Caller owns the memory and must
 * eventually call rustls_client_config_builder_build, then free the
 * resulting rustls_client_config.
 * This uses rustls safe default values
 * for the cipher suites, key exchange groups and protocol versions.
 * This starts out with no trusted roots.
 * Caller must add roots with rustls_client_config_builder_load_roots_from_file
 * or provide a custom verifier.
 */
extern(C) rustls_client_config_builder *rustls_client_config_builder_new();

/**
 * Create a rustls_client_config_builder. Caller owns the memory and must
 * eventually call rustls_client_config_builder_build, then free the
 * resulting rustls_client_config. Specify cipher suites in preference
 * order; the `cipher_suites` parameter must point to an array containing
 * `len` pointers to `rustls_supported_ciphersuite` previously obtained
 * from `rustls_all_ciphersuites_get_entry()`, or to a provided array,
 * RUSTLS_DEFAULT_CIPHER_SUITES or RUSTLS_ALL_CIPHER_SUITES. Set the TLS
 * protocol versions to use when negotiating a TLS session.
 *
 * `tls_version` is the version of the protocol, as defined in rfc8446,
 * ch. 4.2.1 and end of ch. 5.1. Some values are defined in
 * `rustls_tls_version` for convenience, and the arrays
 * RUSTLS_DEFAULT_VERSIONS or RUSTLS_ALL_VERSIONS can be used directly.
 *
 * `versions` will only be used during the call and the application retains
 * ownership. `len` is the number of consecutive `uint16_t` pointed to by `versions`.
 */
extern(C) rustls_result rustls_client_config_builder_new_custom(const rustls_supported_ciphersuite ** cipher_suites,
                                                      size_t cipher_suites_len,
                                                      const ushort *tls_versions,
                                                      size_t tls_versions_len,
                                                      rustls_client_config_builder **builder_out);

/**
 * Set a custom server certificate verifier.
 *
 * The callback must not capture any of the pointers in its
 * rustls_verify_server_cert_params.
 * If `userdata` has been set with rustls_connection_set_userdata, it
 * will be passed to the callback. Otherwise the userdata param passed to
 * the callback will be NULL.
 *
 * The callback must be safe to call on any thread at any time, including
 * multiple concurrent calls. So, for instance, if the callback mutates
 * userdata (or other shared state), it must use synchronization primitives
 * to make such mutation safe.
 *
 * The callback receives certificate chain information as raw bytes.
 * Currently this library offers no functions for C code to parse the
 * certificates, so you'll need to bring your own certificate parsing library
 * if you need to parse them.
 *
 * If you intend to write a verifier that accepts all certificates, be aware
 * that special measures are required for IP addresses. Rustls currently
 * (0.20.0) doesn't support building a ClientConnection with an IP address
 * (because it's not a valid DnsNameRef). One workaround is to detect IP
 * addresses and rewrite them to `example.invalid`, and _also_ to disable
 * SNI via rustls_client_config_builder_set_enable_sni (IP addresses don't
 * need SNI).
 *
 * If the custom verifier accepts the certificate, it should return
 * RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
 * Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
 * section.
 *
 * <https://docs.rs/rustls/0.20.0/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier>
 */
extern(C) rustls_result rustls_client_config_builder_dangerous_set_certificate_verifier(rustls_client_config_builder *config_builder,
                                                                              rustls_verify_server_cert_callback callback);

/**
 * Use the trusted root certificates from the provided store.
 *
 * This replaces any trusted roots already configured with copies
 * from `roots`. This adds 1 to the refcount for `roots`. When you
 * call rustls_client_config_free or rustls_client_config_builder_free,
 * those will subtract 1 from the refcount for `roots`.
 */
extern(C) rustls_result rustls_client_config_builder_use_roots(rustls_client_config_builder *config_builder,
                                                     const rustls_root_cert_store *roots);

/**
 * Add trusted root certificates from the named file, which should contain
 * PEM-formatted certificates.
 */
extern(C) rustls_result rustls_client_config_builder_load_roots_from_file(rustls_client_config_builder *config_builder,
                                                                const char *filename);

/**
 * Set the ALPN protocol list to the given protocols. `protocols` must point
 * to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
 * elements. Each element of the buffer must be a rustls_slice_bytes whose
 * data field points to a single ALPN protocol ID. Standard ALPN protocol
 * IDs are defined at
 * <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
 *
 * This function makes a copy of the data in `protocols` and does not retain
 * any pointers, so the caller can free the pointed-to memory after calling.
 *
 * <https://docs.rs/rustls/0.20.0/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols>
 */
extern(C) rustls_result rustls_client_config_builder_set_alpn_protocols(rustls_client_config_builder *builder,
                                                              const rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Enable or disable SNI.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ClientConfig.html#structfield.enable_sni>
 */
extern(C) void rustls_client_config_builder_set_enable_sni(rustls_client_config_builder *config,
                                                 bool enable);

/**
 * Provide the configuration a list of certificates where the connection
 * will select the first one that is compatible with the server's signature
 * verification capabilities. Clients that want to support both ECDSA and
 * RSA certificates will want the ECSDA to go first in the list.
 *
 * The built configuration will keep a reference to all certified keys
 * provided. The client may `rustls_certified_key_free()` afterwards
 * without the configuration losing them. The same certified key may also
 * be used in multiple configs.
 *
 * EXPERIMENTAL: installing a client authentication callback will replace any
 * configured certified keys and vice versa.
 */
extern(C) rustls_result rustls_client_config_builder_set_certified_key(rustls_client_config_builder *builder,
                                                             const rustls_certified_key **certified_keys,
                                                             size_t certified_keys_len);

/**
 * Turn a *rustls_client_config_builder (mutable) into a const *rustls_client_config
 * (read-only).
 */
extern(C) const(rustls_client_config)* rustls_client_config_builder_build(rustls_client_config_builder *builder);

/**
 * "Free" a client_config_builder without building it into a rustls_client_config.
 * Normally builders are built into rustls_client_config via `rustls_client_config_builder_build`
 * and may not be free'd or otherwise used afterwards.
 * Use free only when the building of a config has to be aborted before a config
 * was created.
 */
extern(C) void rustls_client_config_builder_free(rustls_client_config_builder *config);

/**
 * "Free" a rustls_client_config previously returned from
 * rustls_client_config_builder_build. Since rustls_client_config is actually an
 * atomically reference-counted pointer, extant client connections may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_client_config_free(const rustls_client_config *config);

/**
 * Create a new rustls_connection containing a client connection and return
 * it in the output parameter `out`. If this returns an error code, the
 * memory pointed to by `conn_out` remains unchanged. If this returns a
 * non-error, the memory pointed to by `conn_out` is modified to point at a
 * valid rustls_connection. The caller now owns the rustls_connection and must
 * call `rustls_connection_free` when done with it.
 */
extern(C) rustls_result rustls_client_connection_new(const rustls_client_config *config,
                                           const char *hostname,
                                           rustls_connection **conn_out);

/**
 * Set the userdata pointer associated with this connection. This will be passed
 * to any callbacks invoked by the connection, if you've set up callbacks in the config.
 * The pointed-to data must outlive the connection.
 */
extern(C) void rustls_connection_set_userdata(rustls_connection *conn, void *userdata);

/**
 * Set the logging callback for this connection. The log callback will be invoked
 * with the userdata parameter previously set by rustls_connection_set_userdata, or
 * NULL if no userdata was set.
 */
extern(C) void rustls_connection_set_log_callback(rustls_connection *conn, rustls_log_callback cb);

/**
 * Read some TLS bytes from the network into internal buffers. The actual network
 * I/O is performed by `callback`, which you provide. Rustls will invoke your
 * callback with a suitable buffer to store the read bytes into. You don't have
 * to fill it up, just fill with as many bytes as you get in one syscall.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 * Returns 0 for success, or an errno value on error. Passes through return values
 * from callback. See rustls_read_callback for more details.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.read_tls>
 */
extern(C) rustls_io_result rustls_connection_read_tls(rustls_connection *conn,
                                            rustls_read_callback callback,
                                            void *userdata,
                                            size_t *out_n);

/**
 * Write some TLS bytes to the network. The actual network I/O is performed by
 * `callback`, which you provide. Rustls will invoke your callback with a
 * suitable buffer containing TLS bytes to send. You don't have to write them
 * all, just as many as you can in one syscall.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 * Returns 0 for success, or an errno value on error. Passes through return values
 * from callback. See rustls_write_callback for more details.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.write_tls>
 */
extern(C) rustls_io_result rustls_connection_write_tls(rustls_connection *conn,
                                             rustls_write_callback callback,
                                             void *userdata,
                                             size_t *out_n);

/**
 * Write all available TLS bytes to the network. The actual network I/O is performed by
 * `callback`, which you provide. Rustls will invoke your callback with an array
 * of rustls_slice_bytes, each containing a buffer with TLS bytes to send.
 * You don't have to write them all, just as many as you are willing.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 * Returns 0 for success, or an errno value on error. Passes through return values
 * from callback. See rustls_write_callback for more details.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.Writer.html#method.write_vectored>
 */
extern(C) rustls_io_result rustls_connection_write_tls_vectored(rustls_connection *conn,
                                                      rustls_write_vectored_callback callback,
                                                      void *userdata,
                                                      size_t *out_n);

/**
 * Decrypt any available ciphertext from the internal buffer and put it
 * into the internal plaintext buffer, potentially making bytes available
 * for rustls_connection_read().
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.process_new_packets>
 */
extern(C) rustls_result rustls_connection_process_new_packets(rustls_connection *conn);

/**
 * <https://docs.rs/rustls/0.20.0/rustls/struct.CommonState.html#method.wants_read>
 */
extern(C) bool rustls_connection_wants_read(const rustls_connection *conn);

/**
 * <https://docs.rs/rustls/0.20.0/rustls/struct.CommonState.html#method.wants_write>
 */
extern(C) bool rustls_connection_wants_write(const rustls_connection *conn);

/**
 * <https://docs.rs/rustls/0.20.0/rustls/struct.CommonState.html#method.is_handshaking>
 */
extern(C) bool rustls_connection_is_handshaking(const rustls_connection *conn);

/**
 * Sets a limit on the internal buffers used to buffer unsent plaintext (prior
 * to completing the TLS handshake) and unsent TLS records. By default, there
 * is no limit. The limit can be set at any time, even if the current buffer
 * use is higher.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.set_buffer_limit>
 */
extern(C) void rustls_connection_set_buffer_limit(rustls_connection *conn, size_t n);

/**
 * Queues a close_notify fatal alert to be sent in the next write_tls call.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.send_close_notify>
 */
extern(C) void rustls_connection_send_close_notify(rustls_connection *conn);

/**
 * Return the i-th certificate provided by the peer.
 * Index 0 is the end entity certificate. Higher indexes are certificates
 * in the chain. Requesting an index higher than what is available returns
 * NULL.
 * The returned pointer is valid until the next mutating function call
 * affecting the connection. A mutating function call is one where the
 * first argument has type `struct rustls_connection *` (as opposed to
 *  `const struct rustls_connection *`).
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.peer_certificates>
 */
extern(C) const(rustls_certificate)* rustls_connection_get_peer_certificate(const rustls_connection *conn,
                                                                        size_t i);

/**
 * Get the ALPN protocol that was negotiated, if any. Stores a pointer to a
 * borrowed buffer of bytes, and that buffer's len, in the output parameters.
 * The borrow lives as long as the connection.
 * If the connection is still handshaking, or no ALPN protocol was negotiated,
 * stores NULL and 0 in the output parameters.
 * The provided pointer is valid until the next mutating function call
 * affecting the connection. A mutating function call is one where the
 * first argument has type `struct rustls_connection *` (as opposed to
 *  `const struct rustls_connection *`).
 * <https://www.iana.org/assignments/tls-parameters/>
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.alpn_protocol>
 */
extern(C) void rustls_connection_get_alpn_protocol(const rustls_connection *conn,
                                         const ubyte **protocol_out,
                                         size_t *protocol_out_len);

/**
 * Return the TLS protocol version that has been negotiated. Before this
 * has been decided during the handshake, this will return 0. Otherwise,
 * the u16 version number as defined in the relevant RFC is returned.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.protocol_version>
 * <https://docs.rs/rustls/0.20.0/rustls/internal/msgs/enums/enum.ProtocolVersion.html>
 */
extern(C) ushort rustls_connection_get_protocol_version(const rustls_connection *conn);

/**
 * Retrieves the cipher suite agreed with the peer.
 * This returns NULL until the ciphersuite is agreed.
 * The returned pointer lives as long as the program.
 * <https://docs.rs/rustls/0.20.0/rustls/enum.Connection.html#method.negotiated_cipher_suite>
 */
extern(C) const(rustls_supported_ciphersuite)* rustls_connection_get_negotiated_ciphersuite(const rustls_connection *conn);

/**
 * Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
 * This will increase the number of output bytes available to
 * `rustls_connection_write_tls`.
 * On success, store the number of bytes actually written in *out_n
 * (this may be less than `count`).
 * <https://docs.rs/rustls/0.20.0/rustls/struct.Writer.html#method.write>
 */
extern(C) rustls_result rustls_connection_write(rustls_connection *conn,
                                      const ubyte *buf,
                                      size_t count,
                                      size_t *out_n);

/**
 * Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
 * On success, store the number of bytes read in *out_n (this may be less
 * than `count`). A success with *out_n set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to rustls_connection_read_tls and
 * rustls_connection_process_new_packets."
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.Reader.html#method.read>
 */
extern(C) rustls_result rustls_connection_read(rustls_connection *conn,
                                     ubyte *buf,
                                     size_t count,
                                     size_t *out_n);

version(DEFINE_READ_BUF)
{
/**
 * Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
 * On success, store the number of bytes read in *out_n (this may be less
 * than `count`). A success with *out_n set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to rustls_connection_read_tls and
 * rustls_connection_process_new_packets."
 *
 * This experimental API is only available when using a nightly Rust compiler
 * and enabling the `read_buf` Cargo feature. It will be deprecated and later
 * removed in future versions.
 *
 * Unlike with `rustls_connection_read`, this function may be called with `buf`
 * pointing to an uninitialized memory buffer.
 */
extern(C) rustls_result rustls_connection_read_2(rustls_connection *conn,
                                       ubyte *buf,
                                       size_t count,
                                       size_t *out_n);
}

/**
 * Free a rustls_connection. Calling with NULL is fine.
 * Must not be called twice with the same value.
 */
extern(C) void rustls_connection_free(rustls_connection *conn);

/**
 * After a rustls function returns an error, you may call
 * this to get a pointer to a buffer containing a detailed error
 * message. The contents of the error buffer will be out_n bytes long,
 * UTF-8 encoded, and not NUL-terminated.
 */
extern(C) void rustls_error(uint result, char *buf, size_t len, size_t *out_n);

extern(C) bool rustls_result_is_cert_error(uint result);

/**
 * Return a rustls_str containing the stringified version of a log level.
 */
extern(C) rustls_str rustls_log_level_str(rustls_log_level level);

/**
 * Return the length of the outer slice. If the input pointer is NULL,
 * returns 0.
 */
extern(C) size_t rustls_slice_slice_bytes_len(const rustls_slice_slice_bytes *input);

/**
 * Retrieve the nth element from the input slice of slices. If the input
 * pointer is NULL, or n is greater than the length of the
 * rustls_slice_slice_bytes, returns rustls_slice_bytes{NULL, 0}.
 */
extern(C) rustls_slice_bytes rustls_slice_slice_bytes_get(const rustls_slice_slice_bytes *input,
                                                       size_t n);

/**
 * Return the length of the outer slice. If the input pointer is NULL,
 * returns 0.
 */
extern(C) size_t rustls_slice_str_len(const rustls_slice_str *input);

/**
 * Retrieve the nth element from the input slice of `&str`s. If the input
 * pointer is NULL, or n is greater than the length of the
 * rustls_slice_str, returns rustls_str{NULL, 0}.
 */
extern(C) rustls_str rustls_slice_str_get(const rustls_slice_str *input, size_t n);

/**
 * Create a rustls_server_config_builder. Caller owns the memory and must
 * eventually call rustls_server_config_builder_build, then free the
 * resulting rustls_server_config. This uses rustls safe default values
 * for the cipher suites, key exchange groups and protocol versions.
 */
extern(C) rustls_server_config_builder *rustls_server_config_builder_new();

/**
 * Create a rustls_server_config_builder. Caller owns the memory and must
 * eventually call rustls_server_config_builder_build, then free the
 * resulting rustls_server_config. Specify cipher suites in preference
 * order; the `cipher_suites` parameter must point to an array containing
 * `len` pointers to `rustls_supported_ciphersuite` previously obtained
 * from `rustls_all_ciphersuites_get_entry()`. Set the TLS protocol
 * versions to use when negotiating a TLS session.
 *
 * `tls_version` is the version of the protocol, as defined in rfc8446,
 * ch. 4.2.1 and end of ch. 5.1. Some values are defined in
 * `rustls_tls_version` for convenience.
 *
 * `versions` will only be used during the call and the application retains
 * ownership. `len` is the number of consecutive `uint16_t` pointed to by `versions`.
 */
extern(C) rustls_result rustls_server_config_builder_new_custom(const rustls_supported_ciphersuite **cipher_suites,
                                                      size_t cipher_suites_len,
                                                      const ushort *tls_versions,
                                                      size_t tls_versions_len,
                                                      rustls_server_config_builder **builder_out);

/**
 * Create a rustls_server_config_builder for TLS sessions that require
 * valid client certificates. The passed rustls_client_cert_verifier may
 * be used in several builders.
 * For memory lifetime, see rustls_server_config_builder_new.
 */
extern(C) void rustls_server_config_builder_set_client_verifier(rustls_server_config_builder *builder,
                                                      const rustls_client_cert_verifier *verifier);

/**
 * Create a rustls_server_config_builder for TLS sessions that accept
 * valid client certificates, but do not require them. The passed
 * rustls_client_cert_verifier_optional may be used in several builders.
 * For memory lifetime, see rustls_server_config_builder_new.
 */
extern(C) void rustls_server_config_builder_set_client_verifier_optional(rustls_server_config_builder *builder,
                                                               const rustls_client_cert_verifier_optional *verifier);

/**
 * "Free" a server_config_builder without building it into a rustls_server_config.
 * Normally builders are built into rustls_server_configs via `rustls_server_config_builder_build`
 * and may not be free'd or otherwise used afterwards.
 * Use free only when the building of a config has to be aborted before a config
 * was created.
 */
extern(C) void rustls_server_config_builder_free(rustls_server_config_builder *config);

/**
 * With `ignore` != 0, the server will ignore the client ordering of cipher
 * suites, aka preference, during handshake and respect its own ordering
 * as configured.
 * <https://docs.rs/rustls/0.20.0/rustls/struct.ServerConfig.html#structfield.ignore_client_order>
 */
extern(C) rustls_result rustls_server_config_builder_set_ignore_client_order(rustls_server_config_builder *builder,
                                                                   bool ignore);

/**
 * Set the ALPN protocol list to the given protocols. `protocols` must point
 * to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
 * elements. Each element of the buffer must point to a slice of bytes that
 * contains a single ALPN protocol from
 * <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
 *
 * This function makes a copy of the data in `protocols` and does not retain
 * any pointers, so the caller can free the pointed-to memory after calling.
 *
 * <https://docs.rs/rustls/0.20.0/rustls/server/struct.ServerConfig.html#structfield.alpn_protocols>
 */
extern(C) rustls_result rustls_server_config_builder_set_alpn_protocols(rustls_server_config_builder *builder,
                                                              const rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Provide the configuration a list of certificates where the connection
 * will select the first one that is compatible with the client's signature
 * verification capabilities. Servers that want to support both ECDSA and
 * RSA certificates will want the ECSDA to go first in the list.
 *
 * The built configuration will keep a reference to all certified keys
 * provided. The client may `rustls_certified_key_free()` afterwards
 * without the configuration losing them. The same certified key may also
 * be used in multiple configs.
 *
 * EXPERIMENTAL: installing a client_hello callback will replace any
 * configured certified keys and vice versa.
 */
extern(C) rustls_result rustls_server_config_builder_set_certified_keys(rustls_server_config_builder *builder,
                                                              const rustls_certified_key **certified_keys,
                                                              size_t certified_keys_len);

/**
 * Turn a *rustls_server_config_builder (mutable) into a const *rustls_server_config
 * (read-only).
 */
extern(C) const(rustls_server_config)* rustls_server_config_builder_build(rustls_server_config_builder *builder);

/**
 * "Free" a rustls_server_config previously returned from
 * rustls_server_config_builder_build. Since rustls_server_config is actually an
 * atomically reference-counted pointer, extant server connections may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
extern(C) void rustls_server_config_free(const rustls_server_config *config);

/**
 * Create a new rustls_connection containing a server connection, and return it
 * in the output parameter `out`. If this returns an error code, the memory
 * pointed to by `conn_out` remains unchanged. If this returns a non-error,
 * the memory pointed to by `conn_out` is modified to point
 * at a valid rustls_connection. The caller now owns the rustls_connection
 * and must call `rustls_connection_free` when done with it.
 */
extern(C) rustls_result rustls_server_connection_new(const rustls_server_config *config,
                                           rustls_connection **conn_out);

/**
 * Copy the SNI hostname to `buf` which can hold up  to `count` bytes,
 * and the length of that hostname in `out_n`. The string is stored in UTF-8
 * with no terminating NUL byte.
 * Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.
 * Returns Ok with *out_n == 0 if there is no SNI hostname available on this connection
 * because it hasn't been processed yet, or because the client did not send SNI.
 * <https://docs.rs/rustls/0.20.0/rustls/server/struct.ServerConnection.html#method.sni_hostname>
 */
extern(C) rustls_result rustls_server_connection_get_sni_hostname(const rustls_connection *conn,
                                                        ubyte *buf,
                                                        size_t count,
                                                        size_t *out_n);

/**
 * Register a callback to be invoked when a connection created from this config
 * sees a TLS ClientHello message. If `userdata` has been set with
 * rustls_connection_set_userdata, it will be passed to the callback.
 * Otherwise the userdata param passed to the callback will be NULL.
 *
 * Any existing `ResolvesServerCert` implementation currently installed in the
 * `rustls_server_config` will be replaced. This also means registering twice
 * will overwrite the first registration. It is not permitted to pass a NULL
 * value for `callback`.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 * Installing a client_hello callback will replace any configured certified keys
 * and vice versa. Same holds true for the set_certified_keys variant.
 */
extern(C) rustls_result rustls_server_config_builder_set_hello_callback(rustls_server_config_builder *builder,
                                                              rustls_client_hello_callback callback);

/**
 * Select a `rustls_certified_key` from the list that matches the cryptographic
 * parameters of a TLS client hello. Note that this does not do any SNI matching.
 * The input certificates should already have been filtered to ones matching the
 * SNI from the client hello.
 *
 * This is intended for servers that are configured with several keys for the
 * same domain name(s), for example ECDSA and RSA types. The presented keys are
 * inspected in the order given and keys first in the list are given preference,
 * all else being equal. However rustls is free to choose whichever it considers
 * to be the best key with its knowledge about security issues and possible future
 * extensions of the protocol.
 *
 * Return RUSTLS_RESULT_OK if a key was selected and RUSTLS_RESULT_NOT_FOUND
 * if none was suitable.
 */
extern(C) rustls_result rustls_client_hello_select_certified_key(const rustls_client_hello *hello,
                                                       const rustls_certified_key **certified_keys,
                                                       size_t certified_keys_len,
                                                       const rustls_certified_key **out_key);

/**
 * Register callbacks for persistence of TLS session IDs and secrets. Both
 * keys and values are highly sensitive data, containing enough information
 * to break the security of the connections involved.
 *
 * If `userdata` has been set with rustls_connection_set_userdata, it
 * will be passed to the callbacks. Otherwise the userdata param passed to
 * the callbacks will be NULL.
 */
extern(C) rustls_result rustls_server_config_builder_set_persistence(rustls_server_config_builder *builder,
                                                           rustls_session_store_get_callback get_cb,
                                                           rustls_session_store_put_callback put_cb);
