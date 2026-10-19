// Diagnostic component only. Packet shape is not WG authentication or readiness.
// Caller holds its peer lease until BOTH engine and bridge stop are confirmed.
// Add-Type -Path this file in Windows PowerShell 5 / .NET Framework.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

public sealed class UdpWireObserver : IDisposable
{
    private const SocketOptionName UnicastInterface = (SocketOptionName)31;
    private readonly Socket local, outer;
    private readonly CancellationTokenSource cancel = new CancellationTokenSource();
    private Task worker;
    private long sent, received, type1, type2, type3, type4, nonWg;
    private readonly long[] sizes = new long[8];
    private int faulted, stopped, localClosed, outerClosed;
    public int LocalPort { get; private set; }

    private UdpWireObserver(Socket localSocket, Socket outerSocket)
    {
        local = localSocket; outer = outerSocket;
        LocalPort = ((IPEndPoint)local.LocalEndPoint).Port;
    }

    public static UdpWireObserver Start(string source, int ifIndex, string destination, int port)
    {
        IPAddress src, dst;
        if (ifIndex <= 0 || port <= 0 || port > 65535 ||
            !IPAddress.TryParse(source, out src) || !IPAddress.TryParse(destination, out dst) ||
            !UsableV4(src) || !PublicV4(dst)) throw new ArgumentException("udp_wire_arguments");
        bool matched = false;
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                !nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
            IPInterfaceProperties props = nic.GetIPProperties();
            IPv4InterfaceProperties v4 = props.GetIPv4Properties();
            if (v4 == null || v4.Index != ifIndex) continue;
            foreach (UnicastIPAddressInformation ip in props.UnicastAddresses)
                if (ip.Address.Equals(src)) matched = true;
        }
        if (!matched) throw new InvalidOperationException("udp_wire_source_interface_mismatch");
        Socket inner = null, wire = null;
        try
        {
            wire = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            wire.ExclusiveAddressUse = true;
            int encodedIndex = IPAddress.HostToNetworkOrder(ifIndex);
            wire.SetSocketOption(SocketOptionLevel.IP, UnicastInterface, encodedIndex);
            wire.Bind(new IPEndPoint(src, 0));
            wire.Connect(new IPEndPoint(dst, port));
            IPEndPoint bound = (IPEndPoint)wire.LocalEndPoint;
            if (!bound.Address.Equals(src) || bound.Port == 0 ||
                !wire.RemoteEndPoint.Equals(new IPEndPoint(dst, port)) ||
                // Windows sets this option in network order but returns its index in host order.
                (int)wire.GetSocketOption(SocketOptionLevel.IP, UnicastInterface) != ifIndex)
                throw new InvalidOperationException("udp_wire_binding_readback_failed");
            wire.SendTimeout = 100; wire.Blocking = false;
            inner = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            inner.ExclusiveAddressUse = true;
            inner.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            inner.SendTimeout = 100; inner.Blocking = false;
            UdpWireObserver result = new UdpWireObserver(inner, wire);
            result.worker = Task.Factory.StartNew(result.Forward, CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            return result;
        }
        catch { if (inner != null) inner.Close(); if (wire != null) wire.Close(); throw; }
    }

    private static bool UsableV4(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = ip.GetAddressBytes();
        return b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254);
    }
    private static bool PublicV4(IPAddress ip)
    {
        if (!UsableV4(ip)) return false;
        byte[] b = ip.GetAddressBytes();
        return b[0] != 10 && !(b[0] == 172 && b[1] >= 16 && b[1] <= 31) &&
            !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && b[1] >= 64 && b[1] <= 127) &&
            !(b[0] == 192 && b[1] == 0) && !(b[0] == 198 && (b[1] == 18 || b[1] == 19)) &&
            !(b[0] == 198 && b[1] == 51 && b[2] == 100) &&
            !(b[0] == 203 && b[1] == 0 && b[2] == 113);
    }
    private void Observe(byte[] bytes, int count)
    {
        Interlocked.Increment(ref received);
        int bucket = count == 0 ? 0 : count < 32 ? 1 : count < 64 ? 2 :
            count < 92 ? 3 : count < 148 ? 4 : count < 512 ? 5 : count < 1472 ? 6 : 7;
        Interlocked.Increment(ref sizes[bucket]);
        uint type = count < 4 ? 0 : (uint)bytes[0] | ((uint)bytes[1] << 8) |
            ((uint)bytes[2] << 16) | ((uint)bytes[3] << 24);
        if (type == 1 && count == 148) Interlocked.Increment(ref type1);
        else if (type == 2 && count == 92) Interlocked.Increment(ref type2);
        else if (type == 3 && count == 64) Interlocked.Increment(ref type3);
        else if (type == 4 && count >= 32) Interlocked.Increment(ref type4);
        else Interlocked.Increment(ref nonWg);
    }
    private void Forward()
    {
        byte[] bytes = new byte[65535];
        IPEndPoint client = null;
        try
        {
            while (!cancel.IsCancellationRequested)
            {
                List<Socket> ready = new List<Socket> { local, outer };
                Socket.Select(ready, null, null, 25000);
                foreach (Socket socket in ready)
                {
                    if (cancel.IsCancellationRequested) break;
                    try
                    {
                        if (socket == local)
                        {
                            EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                            int count = local.ReceiveFrom(bytes, ref from);
                            IPEndPoint candidate = (IPEndPoint)from;
                            if (!candidate.Address.Equals(IPAddress.Loopback) || candidate.Port == 0 ||
                                (client != null && !client.Equals(candidate)) || count == 0 || count > 65507) continue;
                            if (client == null) client = candidate;
                            if (outer.Send(bytes, count, SocketFlags.None) != count)
                                throw new InvalidOperationException("udp_wire_partial_datagram");
                            Interlocked.Increment(ref sent);
                        }
                        else
                        {
                            int count = outer.Receive(bytes);
                            Observe(bytes, count);
                            if (client != null && local.SendTo(bytes, 0, count, SocketFlags.None, client) != count)
                                throw new InvalidOperationException("udp_wire_partial_datagram");
                        }
                    }
                    catch (SocketException e) { if (e.SocketErrorCode != SocketError.WouldBlock) throw; }
                }
            }
        }
        catch { if (!cancel.IsCancellationRequested) Interlocked.Exchange(ref faulted, 1); }
        finally
        {
            Array.Clear(bytes, 0, bytes.Length);
            CloseSockets();
        }
    }

    public IDictionary<string, object> Snapshot()
    {
        string[] labels = { "len_0", "len_1_31", "len_32_63", "len_64_91",
            "len_92_147", "len_148_511", "len_512_1471", "len_1472_plus" };
        Dictionary<string, object> result = new Dictionary<string, object>();
        result["sent"] = Interlocked.Read(ref sent); result["received"] = Interlocked.Read(ref received);
        result["wg_type1_148"] = Interlocked.Read(ref type1); result["wg_type2_92"] = Interlocked.Read(ref type2);
        result["wg_type3_64"] = Interlocked.Read(ref type3); result["wg_type4_ge32"] = Interlocked.Read(ref type4);
        result["non_wg_shape"] = Interlocked.Read(ref nonWg);
        for (int i = 0; i < labels.Length; i++) result[labels[i]] = Interlocked.Read(ref sizes[i]);
        result["faulted"] = Interlocked.CompareExchange(ref faulted, 0, 0) != 0;
        result["running"] = worker != null && !worker.IsCompleted;
        result["stop_confirmed"] = Interlocked.CompareExchange(ref stopped, 0, 0) != 0;
        return result;
    }
    public bool Stop(int timeoutMs)
    {
        if (timeoutMs < 0 || timeoutMs > 5000) throw new ArgumentOutOfRangeException("timeoutMs");
        System.Diagnostics.Stopwatch budget = System.Diagnostics.Stopwatch.StartNew();
        cancel.Cancel(); CloseSockets();
        int remaining = Math.Max(0, timeoutMs - (int)budget.ElapsedMilliseconds);
        bool done = (worker == null || worker.Wait(remaining)) &&
            Interlocked.CompareExchange(ref localClosed, 0, 0) == 1 &&
            Interlocked.CompareExchange(ref outerClosed, 0, 0) == 1;
        if (done) Interlocked.Exchange(ref stopped, 1);
        return done;
    }
    private void CloseSockets()
    {
        try { local.Close(); Interlocked.Exchange(ref localClosed, 1); } catch { Interlocked.Exchange(ref faulted, 1); }
        try { outer.Close(); Interlocked.Exchange(ref outerClosed, 1); } catch { Interlocked.Exchange(ref faulted, 1); }
    }
    public void Dispose()
    {
        if (!Stop(5000)) throw new TimeoutException("udp_wire_stop_unconfirmed");
    }
}
