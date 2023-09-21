use pyo3::{prelude::*, types::PyBytes};
use rustls_native_certs;

/// Retrieve a list of system DER root CAs
#[pyfunction]
fn root_der_certificates(py: Python) -> PyResult<Vec<&PyBytes>> {
    let mut roots = Vec::new();

    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        let vec_to_string = cert.as_ref().to_vec();

        let py_bytes = PyBytes::new(py, &vec_to_string);
        roots.push(py_bytes);
    }

    Ok(roots)
}

#[pymodule]
fn _rustls(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(root_der_certificates, m)?)?;
    Ok(())
}
