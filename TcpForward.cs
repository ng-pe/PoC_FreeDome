// PoC Sniff OpenVPN configuration from STDIN and Management Port
// Created with Mono 
// Version 0 (PoC) // Nicolas GOLLET

/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

using System;
using System.Threading;
using System.Net;
using System.Net.Sockets;


namespace openvpn
{
	
	public class MyThreadHandle
{

    int myParam;
    System.IO.StreamWriter filelog = new System.IO.StreamWriter("ThreadPortForward.log",true);
    public MyThreadHandle (int myParam)
    {
		filelog.WriteLine("set mgmt port to {0}", myParam);
		filelog.Flush();
			
        this.myParam = myParam;
    }

    public void SetParam(int param)
    {
        this.myParam = param;
    }

    public void ThreadLoop()
    {
			filelog.WriteLine("start PortForward listen 1234, to {0}", myParam);
			filelog.Flush();
       		PortForward pf = new PortForward("openvpnMgmtOut.log");
			pf.Start(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1234),
               new IPEndPoint(IPAddress.Parse("127.0.0.1"), myParam));
			filelog.WriteLine("PortForward Stopped");
			filelog.Flush();
    }
		
}
	
    public class PortForward
    {
        private readonly Socket MainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        private bool IsStop = true;

        public void Stop()
        {
            IsStop = false;
        }

        private string logfile;

        public PortForward(string logfile)
        {
            this.logfile = logfile;

        }

        public void Start(IPEndPoint local, IPEndPoint remote)
        {
            MainSocket.Bind(local);
            MainSocket.Listen(1234);

            while (IsStop)
            {
                var source = MainSocket.Accept();
                var destination = new PortForward("openvpnMgmtIn.log");
                var state = new State(source, destination.MainSocket);
                destination.Connect(remote, source);
                source.BeginReceive(state.Buffer, 0, state.Buffer.Length, 0, OnDataReceive, state);
            }
        }

        private void Connect(EndPoint remoteEndpoint, Socket destination)
        {
            var state = new State(MainSocket, destination);
            MainSocket.Connect(remoteEndpoint);
            MainSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataReceive, state);

        }

        private void OnDataReceive(IAsyncResult result)
        {
            var state = (State)result.AsyncState;
            try
            {
                var bytesRead = state.SourceSocket.EndReceive(result);
                if (bytesRead > 0)
                {
                    state.DestinationSocket.Send(state.Buffer, bytesRead, SocketFlags.None);
                    state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, 0, OnDataReceive, state);

                    if (bytesRead > 1)
                    {
                        // no sniff null bytes...
                        if (state.Buffer[0] != 0)
                        {
							// save to file...
                            System.IO.FileStream _FileStream =
                           new System.IO.FileStream(this.logfile, System.IO.FileMode.Append,
                                                    System.IO.FileAccess.Write);
                            _FileStream.Write(state.Buffer, 0, bytesRead);
                            
                            _FileStream.Flush();
                            _FileStream.Close();
                        }
                    }


                }
            }
            catch
            {
                state.DestinationSocket.Close();
                state.SourceSocket.Close();
            }
        }



        private class State
        {
            public Socket SourceSocket { get; private set; }
            public Socket DestinationSocket { get; private set; }
            public byte[] Buffer { get; private set; }
            public State(Socket source, Socket destination)
            {
                SourceSocket = source;
                DestinationSocket = destination;
                Buffer = new byte[8192];
            }
        }


    }
}

