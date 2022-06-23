use std::io;
use std::sync::Arc;
use crate::{core, datagram_pipe, downstream, forwarder, log_utils};
use crate::forwarder::Forwarder;
use crate::tcp_forwarder::TcpForwarder;
use crate::udp_forwarder::UdpForwarder;


pub(crate) struct DirectForwarder {
    context: Arc<core::Context>,
    tcp_forwarder: TcpForwarder,
    udp_forwarder: UdpForwarder,
}

impl DirectForwarder {
    pub fn new(
        context: Arc<core::Context>,
    ) -> Self {
        let settings = context.settings.clone();
        Self {
            context,
            tcp_forwarder: TcpForwarder::new(settings.clone()),
            udp_forwarder: UdpForwarder::new(settings),
        }
    }
}

impl Forwarder for DirectForwarder {
    fn tcp_connector(
        &mut self,
        id: log_utils::IdChain<u64>,
        meta: forwarder::TcpConnectionMeta,
    ) -> io::Result<Box<dyn forwarder::TcpConnector>> {
        assert!(meta.auth.is_none());
        self.tcp_forwarder.connect_tcp(id, meta.destination)
    }

    fn make_udp_datagram_multiplexer(
        &mut self,
        id: log_utils::IdChain<u64>,
        meta: forwarder::UdpMultiplexerMeta,
    ) -> io::Result<(
        Arc<dyn forwarder::UdpDatagramPipeShared>,
        Box<dyn datagram_pipe::Source<Output = forwarder::UdpDatagramReadStatus>>,
        Box<dyn datagram_pipe::Sink<Input = downstream::UdpDatagram>>,
    )> {
        assert!(meta.auth.is_none());
        self.udp_forwarder.make_multiplexer(id)
    }

    fn make_icmp_datagram_multiplexer(
        &mut self, id: log_utils::IdChain<u64>
    ) -> io::Result<(
        Box<dyn datagram_pipe::Source<Output = forwarder::IcmpDatagram>>,
        Box<dyn datagram_pipe::Sink<Input = downstream::IcmpDatagram>>,
    )> {
        self.context.icmp_forwarder.as_ref().unwrap().make_multiplexer(id)
    }
}
