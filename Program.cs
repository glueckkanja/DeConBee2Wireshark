using System;
using System.IO.Ports;
using System.Text;
using System.Threading;
using Wireshark;

namespace DeConBee2Wireshark
{
    class Program
    {
        static void Main(string[] args)
        {
            var wiresharkSender = new WiresharkSender("conbee", 0xc3);
            while(!wiresharkSender.isConnected)
            {
                Console.Write("Waiting for Wireshark...   ");
                Thread.Sleep(500);
            }
            Console.WriteLine();
            Console.WriteLine("Wireshark connected.");
            Console.WriteLine();

            var serial = new SerialPort("COM6", 38400, Parity.None, 8, StopBits.One);
            serial.ReadTimeout = -1;
            serial.Open();
            var serialData = new byte[] { 0x2a, 0x04, 0x09, 0x0f, 0x00, 0xe3, 0x2a, 0x02, 0x0b, 0xf2 };
            serial.Write(serialData, 0, serialData.Length);

            while (true)
            {
                int firstByte;
                do
                {
                    firstByte = serial.ReadByte();
                } while (firstByte != 0x2a);

                var bytesToRead = serial.ReadByte();
                serialData = new byte[bytesToRead + 2];
                serialData[0] = (byte)firstByte;
                int bytesRead = 0;
                while (bytesRead < bytesToRead)
                {
                    bytesRead += serial.Read(serialData, 2 + bytesRead, bytesToRead - bytesRead);
                }
                serialData[1] = (byte)bytesRead;

                Console.WriteLine(HexDump(serialData));

                if (serialData[2] == 0x50 && serialData.Length > 12)
                {
                    wiresharkSender.SendToWireshark(serialData, 11, serialData.Length - 12);
                }
            }
        }

        public static string HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            return result.ToString();
        }
    }
}