// Processed by SolutionConv >>>
//
// 本ソースファイルは、公開時の所定の手続きとして一部のセンシティブな情報をマスキングしています。
// 元データの機微に触れる可能性がある箇所を伏せ字化したものであり、
// リリース版との処理内容に実質的な差異が生じない範囲で調整を加えています。
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using HLTStudio.Commons;
using HLTStudio.Tools;

namespace HLTStudio
{
	class Program
	{
		static void Main(string[] args)
		{
			ProcMain.CUIMain(new Program().Main2);
		}

		private void Main2(ArgsReader ar)
		{
			if (ProcMain.DEBUG)
			{
				Main3();
			}
			else
			{
				Main4(ar);
			}
			SCommon.OpenOutputDirIfCreated();
		}

		private void Main3()
		{
#if DEBUG
			// // ////// /// //

			/////////// ////////////// //////// / ////
			/////////// ////////////// //////// / ////
			/////////// ////////////// //////// / ////

			// //
#endif
			SCommon.Pause();
		}

		private void Main4(ArgsReader ar)
		{
			try
			{
				Main5(ar);
			}
			catch (Exception ex)
			{
				ProcMain.WriteLog(ex);

				if (!BatchMode)
					MessageBox.Show(ex.ToString(), $"{Path.GetFileNameWithoutExtension(ProcMain.SelfFile)} / エラー", MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}

		private enum CipherOperation_e
		{
			NOT_ASSIGNED = 1,
			ENCRYPT,
			DECRYPT,
		}

		private class PassphraseExtend_t
		{
			public byte Padding;
			public int Exponent;

			public byte[] RandPart = null;
		}

		// // ////// //

		private bool BatchMode = false;
		private bool SilentMode = false;
		private bool RemoveInputFileMode = false;
		private CipherOperation_e CipherOperation = CipherOperation_e.NOT_ASSIGNED;
		private string Passphrase = null;
		private PassphraseExtend_t PassphraseExtend = null;
		private string InputFilePath = null;
		private string OutputFilePath = null;

		// ////

		private byte[] RawKey;

		private void Main5(ArgsReader ar)
		{
			for (; ; )
			{
				if (ar.ArgIs("/B"))
				{
					BatchMode = true;
					continue;
				}
				if (ar.ArgIs("/S"))
				{
					SilentMode = true;
					continue;
				}
				if (ar.ArgIs("/R"))
				{
					RemoveInputFileMode = true;
					continue;
				}
				if (ar.ArgIs("/E"))
				{
					CipherOperation = CipherOperation_e.ENCRYPT;
					continue;
				}
				if (ar.ArgIs("/D"))
				{
					CipherOperation = CipherOperation_e.DECRYPT;
					continue;
				}
				if (ar.ArgIs("/P"))
				{
					Passphrase = ar.NextArg();
					continue;
				}
				if (ar.ArgIs("/PE"))
				{
					string sxChr = ar.NextArg();
					string sxExp = ar.NextArg();

					int xChr;
					int xExp;

					if (sxChr.Length == 1)
					{
						xChr = (int)sxChr[0];

						if (0xFF < xChr)
							throw new Exception("Bad X-CHR (ASCII)");
					}
					else
					{
						if (!Regex.IsMatch(sxChr, "^[0-9A-Fa-f]{2}$"))
							throw new Exception("Bad X-CHR (HEX)");

						xChr = (int)SCommon.Hex.ToInt(sxChr);
					}

					xExp = int.Parse(sxExp);

					if (xExp < Consts.PE_EXPONENT_MIN || Consts.PE_EXPONENT_MAX < xExp)
						throw new Exception("Bad X-EXP");

					PassphraseExtend = new PassphraseExtend_t()
					{
						Padding = (byte)xChr,
						Exponent = xExp,
					};

					continue;
				}
				break;
			}

			InputFilePath = SCommon.ToFullPath(ar.NextArg());

			if (CipherOperation == CipherOperation_e.NOT_ASSIGNED)
			{
				CipherOperation = CipherOperation_e.ENCRYPT;

				int p = Common.IndexOfExtension(InputFilePath);

				if (p != -1)
				{
					string ext = InputFilePath.Substring(p);

					if (ext.EqualsIgnoreCase(Consts.AUTO_EXT_ENCRYPTED))
					{
						CipherOperation = CipherOperation_e.DECRYPT;
					}
				}
			}

			if (ar.HasArgs())
			{
				OutputFilePath = SCommon.ToFullPath(ar.NextArg());
			}
			else
			{
				if (CipherOperation == CipherOperation_e.ENCRYPT)
				{
					OutputFilePath = InputFilePath + Consts.AUTO_EXT_ENCRYPTED;
				}
				else
				{
					int p = Common.IndexOfExtension(InputFilePath);

					if (p == -1)
						OutputFilePath = InputFilePath + Consts.AUTO_EXT_DECRYPTED;
					else
						OutputFilePath = InputFilePath.Substring(0, p);
				}
			}

			ar.End();

			// // ////// //

			if (Passphrase == null)
				throw new Exception("no Passphrase");

			if (CipherOperation == CipherOperation_e.NOT_ASSIGNED)
				throw new Exception("CipherOperation is NOT_ASSIGNED");

			if (!File.Exists(InputFilePath))
				throw new Exception("InputFilePath not exists");

			if (Directory.Exists(OutputFilePath))
				throw new Exception("OutputFilePath exists as directory");

			// ////

			if (SilentMode)
				ProcMain.WriteLog = message => { };

			ProcMain.WriteLog("-- Parameters --");
			ProcMain.WriteLog($"BatchMode: {BatchMode}");
			ProcMain.WriteLog($"SilentMode: {SilentMode}");
			ProcMain.WriteLog($"RemoveInputFileMode: {RemoveInputFileMode}");
			ProcMain.WriteLog($"Passphrase: \"{Passphrase}\"");
			ProcMain.WriteLog($"PassphraseExtend.Padding: {(PassphraseExtend?.Padding.ToString("x2") ?? "none")}");
			ProcMain.WriteLog($"PassphraseExtend.Exponent: {(PassphraseExtend?.Exponent.ToString() ?? "none")}");
			ProcMain.WriteLog($"CipherOperation: {CipherOperation}");
			ProcMain.WriteLog($"InputFilePath: \"{InputFilePath}\"");
			ProcMain.WriteLog($"OutputFilePath: \"{OutputFilePath}\"");
			ProcMain.WriteLog("----");

			// /////////////
			{
				ProcMain.WriteLog("Read input file testing...");

				using (FileStream reader = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read))
				{
					reader.ReadByte(); // /
					reader.ReadByte(); // /
					reader.ReadByte(); // /
				}

				ProcMain.WriteLog("OK");
			}

			// /////////////
			{
				ProcMain.WriteLog("Write output file testing...");

				File.WriteAllBytes(OutputFilePath, SCommon.EMPTY_BYTES);
				SCommon.DeletePath(OutputFilePath);

				ProcMain.WriteLog("OK");
			}

			if (Regex.IsMatch(Passphrase, "^[0-9A-Fa-f]{128}$"))
			{
				RawKey = SCommon.Hex.I.GetBytes(Passphrase);
			}
			else
			{
				RawKey = SCommon.GetSHA512(writer =>
				{
					SCommon.Write(writer, SCommon.ENCODING_SJIS.GetBytes(Passphrase));

					if (PassphraseExtend != null)
					{
						if (CipherOperation == CipherOperation_e.ENCRYPT)
						{
							PassphraseExtend.RandPart = SCommon.CRandom.GetBytes(Consts.PE_RAND_PART_SIZE);
						}
						else
						{
							using (FileStream reader = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read))
							{
								long fileSize = reader.Length;

								if (fileSize < (long)Consts.PE_RAND_PART_SIZE)
									throw new Exception("Input file broken (fileSize < PE_RAND_PART_SIZE)");

								reader.Seek(fileSize - (long)Consts.PE_RAND_PART_SIZE, SeekOrigin.Begin);

								PassphraseExtend.RandPart = SCommon.Read(reader, Consts.PE_RAND_PART_SIZE);
							}
						}

						SCommon.Write(writer, PassphraseExtend.RandPart);

						{
							const int xChrBuffSizeShift = 20;
							byte[] xChrBuff = new byte[1 << xChrBuffSizeShift];

							for (int i = 0; i < xChrBuff.Length; i++)
								xChrBuff[i] = PassphraseExtend.Padding;

							int wCBCount = 1 << (PassphraseExtend.Exponent - xChrBuffSizeShift);

							ProgressBar pb = new ProgressBar();
							pb.Begin();

							for (int i = 0; i < wCBCount; i++)
							{
								pb.Progress((double)i / wCBCount);

								SCommon.Write(writer, xChrBuff);
							}
							pb.End();
						}
					}
				});
			}

			ProcMain.WriteLog($"RawKey: {SCommon.Hex.I.GetString(RawKey)}");

			bool onMemoryMode = new FileInfo(InputFilePath).Length <= (long)Consts.ON_MEMORY_MODE_FILE_SIZE_MAX;

			ProcMain.WriteLog($"onMemoryMode: {onMemoryMode}");

			try
			{
				switch (CipherOperation)
				{
					case CipherOperation_e.ENCRYPT:
						{
							if (onMemoryMode)
								EncryptMainOnMemory();
							else
								EncryptMainOnStorage();
						}
						break;

					case CipherOperation_e.DECRYPT:
						{
							if (onMemoryMode)
								DecryptMainOnMemory();
							else
								DecryptMainOnStorage();
						}
						break;

					default:
						throw null; // /////
				}
			}
			catch
			{
				ProcMain.WriteLog("DeleteOutputFile.1");

				SCommon.DeletePath(OutputFilePath);

				ProcMain.WriteLog("DeleteOutputFile.2");
				throw;
			}

			ProcMain.WriteLog("done!");
		}

		private void EncryptMainOnMemory()
		{
			byte[] plainData = File.ReadAllBytes(InputFilePath);
			byte[] encryptedData;

			using (RingCipher rc = new RingCipher(RawKey))
			{
				encryptedData = rc.Encrypt(plainData);
			}

			if (PassphraseExtend != null)
			{
				encryptedData = SCommon.Join(new byte[][]
				{
					encryptedData,
					PassphraseExtend.RandPart,
				});
			}

			File.WriteAllBytes(OutputFilePath, encryptedData);

			if (RemoveInputFileMode)
				SCommon.DeletePath(InputFilePath);
		}

		private void EncryptMainOnStorage()
		{
			if (RemoveInputFileMode)
				File.Move(InputFilePath, OutputFilePath);
			else
				File.Copy(InputFilePath, OutputFilePath);

			using (RingCipherFile rc = new RingCipherFile(RawKey))
			{
				rc.Encrypt(OutputFilePath);
			}

			if (PassphraseExtend != null)
			{
				using (FileStream writer = new FileStream(OutputFilePath, FileMode.Append, FileAccess.Write))
				{
					SCommon.Write(writer, PassphraseExtend.RandPart);
				}
			}
		}

		private void DecryptMainOnMemory()
		{
			byte[] encryptedData = File.ReadAllBytes(InputFilePath);
			byte[] decryptedData;

			if (PassphraseExtend != null)
				encryptedData = SCommon.GetPart(encryptedData, 0, encryptedData.Length - Consts.PE_RAND_PART_SIZE);

			using (RingCipher rc = new RingCipher(RawKey))
			{
				decryptedData = rc.Decrypt(encryptedData);
			}

			File.WriteAllBytes(OutputFilePath, decryptedData);

			if (RemoveInputFileMode)
				SCommon.DeletePath(InputFilePath);
		}

		private void DecryptMainOnStorage()
		{
			if (RemoveInputFileMode)
				File.Move(InputFilePath, OutputFilePath);
			else
				File.Copy(InputFilePath, OutputFilePath);

			if (PassphraseExtend != null)
			{
				using (FileStream writer = new FileStream(OutputFilePath, FileMode.Open, FileAccess.Write))
				{
					long newFileSize = writer.Length - (long)Consts.PE_RAND_PART_SIZE;

					if (newFileSize < 0L)
						throw null; // /////

					writer.SetLength(newFileSize);
				}
			}

			using (RingCipherFile rc = new RingCipherFile(RawKey))
			{
				rc.Decrypt(OutputFilePath);
			}
		}
	}
}

//
// <<< Processed by SolutionConv
//