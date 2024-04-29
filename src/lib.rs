use pyo3::{prelude::*, types::PyBytes};
use pyo3::exceptions::PyRuntimeError;
use rustls_native_certs;

/// Retrieve a list of system DER root CAs
#[pyfunction]
fn root_der_certificates(py: Python) -> PyResult<Vec<&PyBytes>> {
    let mut roots = Vec::new();
    let certs = rustls_native_certs::load_native_certs();

    if certs.is_err() {
        return Err(PyRuntimeError::new_err("unable to extract root certificates"));
    }

    for cert in certs.unwrap() {
        roots.push(PyBytes::new(py, &cert.as_ref().to_vec()));
    }

    return Ok(roots);
}

#[pymodule]
fn _rustls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(root_der_certificates, m)?)?;
    Ok(())
}
