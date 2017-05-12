// MIT License
//
// Copyright(c) 2017 Glueck & Kanja Consulting AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using HexDump;
using Mono.Options;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Threading;
using Wireshark;

namespace DeConBee2Wireshark
{
    class Program
    {
        static TextWriter TextOutput = Console.Error;
        static bool Verbose = false;
        static SerialPort ComPort;

        static void Main(string[] args)
        {
            // parse command line options

            string serialPortName = SerialPort.GetPortNames().FirstOrDefault();
            string pipeName = "conbee";
            byte zigBeeChannel = 15;
            string wiresharkExe = "";

            var options = new OptionSet();
            options.Add(new OptionSet.Category("USAGE: DeConBee2Wireshark [options]"));
            options.Add("p|port=", "Serial Port (e.g. 'COM3', default is first available serial port)", x => serialPortName = x);
            options.Add("i|pipe=", String.Format(@"Pipe Name (defaults to '{0}' => '\\.\pipe\{0}')", pipeName), x => pipeName = x);
            options.Add("c|channel=", String.Format("ZigBee Channel to Listen on (defaults to {0})", zigBeeChannel), (byte x) => zigBeeChannel = x);
            options.Add("w|wireshark=", "Path to Wireshark.exe", x => wiresharkExe = x);
            options.Add("v|verbose", "Show Verbose Output", x => Verbose = true);
            options.Add("h|?|help", x => ShowHelpAndExit(options));
            options.Add(new OptionSet.Category(""));
            options.Add(new OptionSet.Category("IMPORTANT: You need a ConBee USB stick from dresden elektronik (www.dresden-elektronik.de) WITH BITCATCHER FIRMWARE for this tool to work!"));

            try
            {
                var unprocessed = options.Parse(args);
                if (unprocessed.Count > 0)
                    throw new ArgumentException(string.Format("Unrecognized command line arguments {0}.",
                        String.Join(" ", unprocessed.Select(x => String.Format("'{0}'", x)))
                    ));
            }
            catch (Exception e)
            {
                ShowHelpAndExit(options, e.Message);
            }


            // connect to ConBee USB stick

            try
            {
                if (string.IsNullOrWhiteSpace(serialPortName))
                    throw new ApplicationException("No serial port found or provided");

                ComPort = new SerialPort(serialPortName, 38400, Parity.None, 8, StopBits.One);
                ComPort.Open();
            }
            catch (Exception ex)
            {
                throw new ApplicationException("Error opening serial port", ex);
            }

            
            // open pipe and wait for wireshark to connect

            TextOutput.WriteLine("DeConBee2Wireshark started (port '{0}', pipe '{1}', zigbee channel {2})", serialPortName, pipeName, zigBeeChannel);
            TextOutput.WriteLine();

            var wiresharkSender = new WiresharkSender(pipeName, 0xc3);

            bool wiresharkIsChild = !string.IsNullOrWhiteSpace(wiresharkExe);
            if (wiresharkIsChild)
            {
                try
                {
                    Process.Start(wiresharkExe, String.Format(@"-i\\.\pipe\{0} -k", pipeName));
                }
                catch (Exception ex)
                {
                    throw new ApplicationException("Error starting Wireshark", ex);
                }
            }
            else
            {
                TextOutput.WriteLine(@"Now start Wireshark with command line arguments -i\\.\pipe\{0} -k", pipeName);
                TextOutput.WriteLine();
            }

            TextOutput.Write(@"Waiting for Wireshark to connect to pipe \\.\pipe\{0}: ", pipeName);
            while (!wiresharkSender.isConnected)
            {
                if (!wiresharkIsChild)
                    TextOutput.Write(".");
                Thread.Sleep(500);
            }
            if (!wiresharkIsChild)
                TextOutput.WriteLine();

            TextOutput.WriteLine("Wireshark connected.");
            TextOutput.WriteLine();

            // discard any old frames
            ComPort.DiscardOutBuffer();
            ComPort.DiscardInBuffer();

            // select channel
            ConBeeSendFrame(new byte[] { 0x09, zigBeeChannel, 0x00 });

            // start sniffing
            try
            {
                ConBeeSendFrame(new byte[] { 0x0b });

                ComPort.ReadTimeout = 1000;
                var frameAck = ConBeeReadFrame();
                if (frameAck[0] != 0x0c)
                    throw new InvalidDataException();
            }
            catch (Exception ex)
            {
                throw new ApplicationException(String.Format("None or invalid data received from COM port. Are you sure a dresden elektronik ConBee USB stick WITH BITCATCHER FIRMWARE is connected to port {0}?", serialPortName), ex);
            }

            // read frames and forward to wireshark
            ComPort.ReadTimeout = SerialPort.InfiniteTimeout;
            while (true)
            {
                var payload = ConBeeReadFrame();
                if (payload[0] == 0x50 && payload.Length > 9)
                {
                    var result = wiresharkSender.SendToWireshark(payload, 9, payload.Length - 9);
                    if (!result)
                    {
                        TextOutput.WriteLine();
                        TextOutput.WriteLine("Pipe broken, Wireshark might have exited - exiting as well.");
                        break;
                    }
                }
            }
        }

        public static void ShowHelpAndExit(OptionSet options, string errorMessage = null)
        {
            TextOutput.WriteLine();
            if (!string.IsNullOrWhiteSpace(errorMessage))
                TextOutput.WriteLine("ERROR: {0}\r\n", errorMessage);
            options.WriteOptionDescriptions(TextOutput);

            Environment.Exit(-666);
        }

        static void ConBeeSendFrame(byte[] payload)
        {
            var fullFrame = new byte[payload.Length + 3];
            fullFrame[0] = 0x2a;
            fullFrame[1] = (byte)(payload.Length + 1);
            Buffer.BlockCopy(payload, 0, fullFrame, 2, payload.Length);

            byte frameChecksum = 0xff;
            for (var i = 1; i < fullFrame.Length - 1; i++)
                frameChecksum -= fullFrame[i];
            fullFrame[fullFrame.Length - 1] = frameChecksum;

            if (Verbose)
            {
                TextOutput.WriteLine("Out:");
                TextOutput.WriteLine(Utils.HexDump(fullFrame));
            }

            ComPort.Write(fullFrame, 0, fullFrame.Length);
        }

        static byte[] ConBeeReadFrame()
        {
            int frameDelimiter = -1;
            while (frameDelimiter != 0x2a)
            {
                frameDelimiter = ComPort.ReadByte();
            }
            var frameLength = ComPort.ReadByte();

            var fullFrame = new byte[frameLength + 2];
            fullFrame[0] = (byte)frameDelimiter;
            fullFrame[1] = (byte)frameLength;

            int bytesRead = 0;
            while (bytesRead < frameLength)
            {
                bytesRead += ComPort.Read(fullFrame, 2 + bytesRead, frameLength - bytesRead);
            }

            if (Verbose)
            {
                TextOutput.WriteLine("In:");
                TextOutput.WriteLine(Utils.HexDump(fullFrame));
            }
            else
            {
                TextOutput.Write(".");
            }

            var payload = new byte[fullFrame[1] - 1];
            Buffer.BlockCopy(fullFrame, 2, payload, 0, payload.Length);

            return payload;
        }
    }
}