using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace _1953_KGB_Unleashed
{
    class FileData
    {
        public byte[] CryptedData { get; set; }
        public byte[] MD5 { get; internal set; }
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            string[]? files = null;
            if (args.Length > 0)
            {
                files = args.SelectMany(arg => File.Exists(arg) ? new string[] { arg }
                                             : Directory.Exists(arg) ? Directory.EnumerateFiles(arg, "*.dat", SearchOption.TopDirectoryOnly) : new string[0]).ToArray();
            }
            if ((files?.Length ?? 0) == 0)
                return;

            // Load known filenames and generate their MD5 lookups
            Dictionary<UInt128, string> FileNames = new Dictionary<UInt128, string>();
            Dictionary<string, UInt128> FileNamesRev = new Dictionary<string, UInt128>();
            foreach (string line in File.ReadAllLines(Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), @"filenames.txt")))
            {
                // prepare filepaths
                string filename = line.ToUpperInvariant().Replace('/', '\\').Trim();

                // don't waste time hashing filenames we already have
                if (FileNamesRev.ContainsKey(filename))
                    continue;

                // MD5 hash the filepath prefixed with a DWORD length of the string
                MD5 md5 = MD5.Create();
                byte[] buf = new byte[filename.Length + 4];
                BitConverter.GetBytes(filename.Length).CopyTo(buf, 0);
                Array.Copy(Encoding.ASCII.GetBytes(filename), 0, buf, 4, filename.Length);
                byte[] hashBytes = MD5.HashData(buf);

                // store the MD5 in a UInt128 so we can use it as a dictionary key because we're too lazy to implement a binary searchable sorted collection
                UInt128 hash = new UInt128(BitConverter.ToUInt64(hashBytes, 8), BitConverter.ToUInt64(hashBytes, 0));
                
                // store MD5 and string pairs
                FileNames.Add(hash, filename);
                FileNamesRev.Add(filename, hash);
            }

            //foreach (var rec in FileNames.Keys.OrderBy(dr => dr))
            //{
            //    Console.WriteLine(@$"{rec:X32} = {FileNames[rec]}");
            //}

            int MaxFilenameLength = FileNamesRev.Keys.Max(dr => dr.Length);
            if (MaxFilenameLength < 34)
                MaxFilenameLength = 34;
            const UInt32 TOC_RECORD_SIZE = 32;
            const UInt32 SECTOR_SIZE = 0x1000; // Used for header and TOC data, must be power of 2
            const UInt32 AES_BLOCK_SIZE = 16; // AES strip reading size, used for alignment, must be power of 2

            foreach (string file in files!)
            {
                string filename = Path.GetFileName(file);
                Console.WriteLine(@$"File:       {filename}");

                Dictionary<UInt128, FileData> FileData = new Dictionary<UInt128, FileData>();

                using (FileStream fs = File.OpenRead(file))
                {
                    byte[] HeaderBuffer = new byte[16];
                    fs.Read(HeaderBuffer, 0, 16);
                    UInt32 Magic = BitConverter.ToUInt32(HeaderBuffer, 0x0);
                    UInt32 Version = BitConverter.ToUInt32(HeaderBuffer, 0x4);
                    UInt32 HUnk2 = BitConverter.ToUInt32(HeaderBuffer, 0x8);
                    UInt32 HUnk3 = BitConverter.ToUInt32(HeaderBuffer, 0xC);
                    Console.WriteLine($"MAGIC:      0x{Magic:X8} '{Encoding.ASCII.GetString(BitConverter.GetBytes(Magic).ToArray())}'");

                    switch(Magic)
                    {
                        case 0x53464352: // RCFS
                            break;
                        case 0x53464653: // SFFS
                            Console.WriteLine("The Russian version \"Phobos 1953\" is procted by StarForce.");
                            Console.WriteLine("Use \"SFFS-Unpacker\" or similar tools for these files.");
                            Console.WriteLine();
                            //break;
                            continue;
                        default:
                            Console.WriteLine("Not an RCFS file.");
                            Console.WriteLine();
                            continue;
                    }

                    Console.WriteLine($"Version?:   0x{Version:X8} ({Version})");
                    Console.WriteLine($"HeaderUnk2: 0x{HUnk2:X8}");
                    Console.WriteLine($"HeaderUnk3: 0x{HUnk3:X8}");

                    byte[] ArchiveKey;
                    byte[] ArchiveIV;

                    {
                        // MD5 & SHA256 hash the filepath prefixed with a DWORD length of the string
                        byte[] buf = new byte[filename.Length + 4];
                        BitConverter.GetBytes(filename.Length).CopyTo(buf, 0);
                        Array.Copy(Encoding.ASCII.GetBytes(filename), 0, buf, 4, filename.Length);

                        SHA256 sha256 = SHA256.Create();
                        ArchiveKey = sha256.ComputeHash(buf);

                        MD5 md5 = MD5.Create();
                        ArchiveIV = md5.ComputeHash(buf);
                    }

                    Console.WriteLine(@$"Key:        {BitConverter.ToString(ArchiveKey).Replace("-", string.Empty)}");
                    Console.WriteLine(@$"IV:         {BitConverter.ToString(ArchiveIV).Replace("-", string.Empty)}");

                    using (Aes aesAlg = Aes.Create())
                    {
                        aesAlg.Key = ArchiveKey;
                        aesAlg.IV = ArchiveIV;
                        aesAlg.Mode = CipherMode.CBC; // XOR chain

                        using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                            using (BinaryReader br = new BinaryReader(csDecrypt))
                            {
                                UInt32 RecordCount = br.ReadUInt32();
                                UInt32 RecordCountPad = br.ReadUInt32();
                                Console.Write($"Records: 0x");
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.Write($"{RecordCountPad:X8}");
                                Console.ResetColor();
                                Console.WriteLine($"{RecordCount:X8} ({RecordCount})");

                                UInt32 Size = br.ReadUInt32();
                                UInt32 SizePad = br.ReadUInt32();
                                Console.Write($"Size:    0x");
                                Console.ForegroundColor = ConsoleColor.DarkGray;
                                Console.Write($"{SizePad:X8}");
                                Console.ResetColor();
                                Console.WriteLine($"{Size:X8} ({Size})");

                                UInt32 ReadBufferSize = ((RecordCount * 32 + TOC_RECORD_SIZE + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1));

                                byte[] FilenameMD5 = new byte[16];
                                byte[] FileRecordCrypt = new byte[16];
                                for (int RecordIdx = 0; RecordIdx < RecordCount; RecordIdx++)
                                {
                                    csDecrypt.Read(FilenameMD5, 0, 16);
                                    csDecrypt.Read(FileRecordCrypt, 0, 16);
                                    FileData.Add(
                                        new UInt128(BitConverter.ToUInt64(FilenameMD5, 8), BitConverter.ToUInt64(FilenameMD5, 0)),
                                        new FileData()
                                        {
                                            CryptedData = FileRecordCrypt.ToArray(), // clone the array by remaking it
                                            MD5 = FilenameMD5.ToArray(),
                                        });
                                }

                                byte[] _ = new byte[16];
                                // Read the rest of the block, which will error if we have any AES failures but with success will be all 0x00s
                                while (fs.Position < ReadBufferSize)
                                {
                                    csDecrypt.Read(_, 0, 16);
                                    if (_.Any(dx => dx != 0x00))
                                        throw new Exception("Decryption Failure");
                                }
                            }
                        }
                    }
                }
                {
                    Console.WriteLine(@$"{"Filename".PadRight(MaxFilenameLength)} |       Offset       |       Length       ");
                    Console.WriteLine(@$"{new string('-', MaxFilenameLength)}-+--------------------+--------------------");
                    //foreach (var kv in FileData.OrderBy(dr => dr.Key))
                    foreach (var kv in FileData)
                    {
                        string? decodedFilename = null;
                        if (FileNames.ContainsKey(kv.Key))
                            decodedFilename = FileNames[kv.Key];

                        byte[]? decryptedData = null;

                        byte[]? FileKey = null;

                        if (decodedFilename != null)
                        {
                            SHA256 sha256 = SHA256.Create();
                            byte[] tmpBuf = new byte[decodedFilename.Length + 4];
                            BitConverter.GetBytes(decodedFilename.Length).CopyTo(tmpBuf, 0);
                            Array.Copy(Encoding.ASCII.GetBytes(decodedFilename).Reverse().ToArray(), 0, tmpBuf, 4, decodedFilename.Length);
                            FileKey = sha256.ComputeHash(tmpBuf);

                            using (Aes aesAlg = Aes.Create())
                            {
                                aesAlg.Key = FileKey;
                                aesAlg.IV = new byte[16];
                                aesAlg.Mode = CipherMode.ECB; // we're only processing 16 bytes, nothing to XOR chain
                                aesAlg.Padding = PaddingMode.None;

                                using (MemoryStream ms = new MemoryStream(kv.Value.CryptedData))
                                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                                using (CryptoStream csDecrypt = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                                {
                                    decryptedData = new byte[16];
                                    csDecrypt.Read(decryptedData, 0, decryptedData.Length);
                                }
                            }

                            UInt32 Offset = BitConverter.ToUInt32(decryptedData, 0x0);
                            UInt32 OffsetPad = BitConverter.ToUInt32(decryptedData, 0x4); // maybe it's 64bit numbers?
                            Console.Write(@$"{decodedFilename.PadRight(MaxFilenameLength)} | 0x");
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.Write(@$"{OffsetPad:X8}");
                            Console.ResetColor();
                            Console.Write(@$"{Offset:X8} | ");

                            UInt32 Size = BitConverter.ToUInt32(decryptedData, 0x8);
                            UInt32 SizePad = BitConverter.ToUInt32(decryptedData, 0xC); // maybe it's 64bit numbers?
                            Console.Write(@"0x");
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.Write(@$"{SizePad:X8}");
                            Console.ResetColor();
                            Console.Write($@"{Size:X8}");
                            Console.WriteLine();
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.Write(@$"<{kv.Key:X32}>{new string(' ', MaxFilenameLength - 34)}");
                            Console.ResetColor();
                            Console.Write(@$" | ");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write($"!{BitConverter.ToString(kv.Value.CryptedData.Take(8).ToArray()).Replace("-", string.Empty)}!");
                            Console.ResetColor();
                            Console.Write($" | ");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write($"!{BitConverter.ToString(kv.Value.CryptedData.Skip(8).ToArray()).Replace("-", string.Empty)}!");
                            Console.ResetColor();
                            Console.WriteLine();
                        }

                        if (decryptedData != null)
                        {
                            // could store this into the record but for now we'll just re-grab them from the decryptedData
                            UInt32 Offset = BitConverter.ToUInt32(decryptedData, 0x0);
                            UInt32 UNK1 = BitConverter.ToUInt32(decryptedData, 0x4); // maybe it's 64bit numbers?
                            UInt32 Size = BitConverter.ToUInt32(decryptedData, 0x8);
                            UInt32 Unk2 = BitConverter.ToUInt32(decryptedData, 0xC); // maybe it's 64bit numbers?

                            UInt32 StartAddress = Offset & ~(AES_BLOCK_SIZE - 1);
                            UInt32 ReadSize = ((Offset + Size + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1)) - (Offset & ~(AES_BLOCK_SIZE - 1));

                            byte[] Buffer = new byte[ReadSize + AES_BLOCK_SIZE]; // not sure why we need a bit more buffer, but we do

                            using (Aes aesAlg = Aes.Create())
                            {
                                aesAlg.Key = FileKey!; // if the data's decrypted the key is known so assume not null (!)
                                aesAlg.IV = new byte[16];
                                aesAlg.Mode = CipherMode.ECB; // don't do the rolling xor, instead we'll do manual XORs of the offset to the first DWORD

                                using (FileStream fs = File.OpenRead(file))
                                {
                                    fs.Seek(StartAddress, SeekOrigin.Begin); // seek past the header

                                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                                    using (CryptoStream csDecrypt = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                                    using (BinaryReader br = new BinaryReader(csDecrypt))
                                    {
                                        // Could copy the bytes 16 bytes at a time (after skipping the lead-in) out if needed
                                        csDecrypt.Read(Buffer, 0, Buffer.Length);
                                        for (int i = 0; i < Buffer.Length; i += (int)AES_BLOCK_SIZE)
                                        {
                                            Buffer[i + 0] ^= (byte)(((StartAddress + i) >> 0x00) & 0xFF);
                                            Buffer[i + 1] ^= (byte)(((StartAddress + i) >> 0x08) & 0xFF);
                                            Buffer[i + 2] ^= (byte)(((StartAddress + i) >> 0x10) & 0xFF);
                                            Buffer[i + 3] ^= (byte)(((StartAddress + i) >> 0x18) & 0xFF);
                                        }
                                    }
                                }
                            }

                            string outPath = Path.GetDirectoryName(decodedFilename);
                            //if (string.IsNullOrEmpty(outPath))
                            //    outPath = "root";
                            //outPath = Path.Combine(Path.GetFileName(file), outPath);
                            if (!string.IsNullOrEmpty(outPath) && !Directory.Exists(outPath))
                                Directory.CreateDirectory(outPath);
                            //using (FileStream fso = File.Create(Path.Combine(Path.GetFileName(file), decodedFilename)))
                            using (FileStream fso = File.Create(decodedFilename))
                                fso.Write(Buffer, (int)(Offset - StartAddress), (int)Size);
                        }
                    }
                }

                Console.WriteLine();
            }
        }
    }
}
