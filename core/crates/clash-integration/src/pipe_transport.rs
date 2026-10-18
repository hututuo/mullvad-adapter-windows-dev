//! Reuse the pinned HTTP parser/framing over a local byte pipe. No TCP bridge,
//! secret header, environment proxy, redirects, or extra listening endpoint.
use adapter_platform::windows_control_pipe::LocalControlPipe;
use std::{
    io::{Read, Write},
    time::Duration,
};
use ureq::{
    unversioned::transport::{
        Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
    },
    Error,
};

#[derive(Debug)]
pub(crate) struct PipeConnector(pub String);
#[derive(Debug)]
pub(crate) struct PipeTransport {
    pipe: LocalControlPipe,
    buffers: LazyBuffers,
}
fn wait(timeout: NextTimeout) -> Duration {
    (*timeout.after).min(Duration::from_secs(5))
}
fn error(error: std::io::Error, timeout: NextTimeout) -> Error {
    if error.kind() == std::io::ErrorKind::TimedOut {
        Error::Timeout(timeout.reason)
    } else {
        error.into()
    }
}
impl Connector for PipeConnector {
    type Out = PipeTransport;
    fn connect(
        &self,
        details: &ConnectionDetails,
        _: Option<()>,
    ) -> Result<Option<Self::Out>, Error> {
        // A virtual URI is used only for HTTP framing. This connector never
        // opens a network socket or delegates to the default TCP connector.
        if details.uri.scheme_str() != Some("http")
            || details.uri.host() != Some("127.0.0.1")
            || details.uri.port_u16() != Some(1)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "local_control_required",
            )
            .into());
        }
        let pipe = LocalControlPipe::connect(&self.0, wait(details.timeout))
            .map_err(|e| error(e, details.timeout))?;
        Ok(Some(PipeTransport {
            pipe,
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
        }))
    }
}
impl Transport for PipeTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        self.pipe.set_timeout(wait(timeout));
        self.pipe
            .write_all(&self.buffers.output()[..amount])
            .map_err(|e| error(e, timeout))
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        self.pipe.set_timeout(wait(timeout));
        let amount = self
            .pipe
            .read(self.buffers.input_append_buf())
            .map_err(|e| error(e, timeout))?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }
    fn is_open(&mut self) -> bool {
        false
    } // Never pool a control connection.
}
