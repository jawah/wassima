use pyo3::exceptions::PyRuntimeError;
use pyo3::{prelude::*, types::PyBytes};

/// Retrieve a list of system DER root CAs
#[pyfunction]
fn root_der_certificates(py: Python) -> PyResult<Vec<Bound<'_, PyBytes>>> {
    let mut roots = Vec::new();
    let certs = rustls_native_certs::load_native_certs();

    if certs.is_err() {
        return Err(PyRuntimeError::new_err(
            "unable to extract root certificates",
        ));
    }

    for cert in certs.unwrap() {
        roots.push(PyBytes::new(py, cert.as_ref()));
    }

    Ok(roots)
}

#[pymodule]
fn _rustls(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(root_der_certificates, m)?)?;
    Ok(())
}
