use pyo3::exceptions::PyRuntimeError;
use pyo3::{prelude::*, types::PyBytes};

/// Retrieve a list of system DER root CAs
#[pyfunction]
fn root_der_certificates(py: Python) -> PyResult<Vec<Bound<'_, PyBytes>>> {
    let mut roots = Vec::new();

    let container = rustls_native_certs::load_native_certs();

    if container.certs.is_empty() {
        return Err(PyRuntimeError::new_err("Failed to load native cert store"));
    }

    for cert in container.certs {
        roots.push(PyBytes::new(py, cert.as_ref()));
    }

    Ok(roots)
}

#[pymodule(gil_used = false)]
fn _rustls(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(root_der_certificates, m)?)?;
    Ok(())
}
