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
using System.IO;
using System.Security.Cryptography;
using HLTStudio.Commons;

namespace HLTStudio.Tools
{
	/// /////////
	/// ///////////////
	/// ///// ///////////// / ///////////////// ////////////////////////
	/// //////////
	public class RingCipherFile : IDisposable
	{
		private AESCipher[] Transformers;

		/// /////////
		/// /////
		/// //  // /// //
		/// //  // /// //
		/// //  // /// //
		/// //  // /// /// //
		/// //  // /// /// //
		/// //  // /// /// //
		/// //  // /// /// //
		/// //  // /// /// /// //
		/// //  // /// /// /// //
		/// //  // /// /// /// //
		/// //  // /// /// /// //
		/// // /// /// /// /// /// //
		/// // /// /// /// /// /// //
		/// // /// /// /// /// /// //
		/// // /// /// /// /// /// //
		/// // ///
		/// //////////
		/// ////// ///////////////////////
		public RingCipherFile(byte[] rawKey)
		{
			if (
				rawKey == null ||
				rawKey.Length < 16 ||
				rawKey.Length % 8 != 0
				)
				throw new Exception("Bad rawKey");

			List<AESCipher> dest = new List<AESCipher>();

			for (int offset = 0; offset < rawKey.Length;)
			{
				int size = rawKey.Length - offset;

				if (48 <= size)
					size = 32;
				else if (size == 40)
					size = 24;

				dest.Add(new AESCipher(SCommon.GetPart(rawKey, offset, size)));
				offset += size;
			}
			this.Transformers = dest.ToArray();
		}

		public void Dispose()
		{
			if (this.Transformers != null)
			{
				foreach (AESCipher transformer in this.Transformers)
					transformer.Dispose();

				this.Transformers = null;
			}
		}

		/// /////////
		/// ///////
		/// //////////
		/// ////// ///////////////////////////
		public void Encrypt(string file)
		{
			ProcMain.WriteLog("ファイルの暗号化を開始しました。");

			if (
				string.IsNullOrEmpty(file) ||
				!File.Exists(file)
				)
				throw new Exception("Bad file");

			AddPadding(file);
			AddCRandPart(file, 64);
			AddHash(file);
			AddCRandPart(file, 16);

			for (int index = 0; index < this.Transformers.Length; index++)
				EncryptRingCBC(file, this.Transformers[index], index, this.Transformers.Length);

			ProcMain.WriteLog("ファイルの暗号化を終了しました。");
		}

		/// /////////
		/// //////
		/// //////////////////////////////
		/// // ///////////////////////////////////
		/// //////////
		/// ////// ///////////////////////////
		public void Decrypt(string file)
		{
			ProcMain.WriteLog("ファイルの復号を開始しました。");

			if (
				string.IsNullOrEmpty(file) ||
				!File.Exists(file)
				)
				throw new Exception("Bad file");

			long fileSize = new FileInfo(file).Length;

			if (
				fileSize < 16 + 64 + 64 + 16 || // / /////////////////////// / //////////// / /////// / //////////// ////
				fileSize % 16 != 0
				)
				throw new Exception("入力データの破損を検出しました。");

			for (int index = 0; index < this.Transformers.Length; index++)
				DecryptRingCBC(file, this.Transformers[this.Transformers.Length - 1 - index], index, this.Transformers.Length);

			RemoveCRandPart(file, 16);
			RemoveHash(file);
			RemoveCRandPart(file, 64);
			RemovePadding(file);

			ProcMain.WriteLog("ファイルの復号を終了しました。");
		}

		private static void AddPadding(string file)
		{
			long fileSize = new FileInfo(file).Length;
			int size = 16 - (int)(fileSize % 16);
			byte[] padding = SCommon.CRandom.GetBytes(size);
			size--;
			padding[size] &= 0xf0;
			padding[size] |= (byte)size;
			AppendBytes(file, padding);
		}

		private static void RemovePadding(string file)
		{
			using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
			{
				long fileSize = stream.Length;

				if (fileSize < 1)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.Seek(fileSize - 1, SeekOrigin.Begin);
				int size = stream.ReadByte() & 0x0f;
				size++;

				if (fileSize < size)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.SetLength(fileSize - size);
			}
		}

		private static void AddCRandPart(string file, int size)
		{
			byte[] padding = SCommon.CRandom.GetBytes(size);
			AppendBytes(file, padding);
		}

		private static void RemoveCRandPart(string file, int size)
		{
			using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
			{
				long fileSize = stream.Length;

				if (fileSize < size)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.SetLength(fileSize - size);
			}
		}

		private const int HASH_SIZE = 64;

		private static void AddHash(string file)
		{
			byte[] hash = SCommon.GetSHA512File(file);

			if (hash.Length != HASH_SIZE)
				throw null; // /////

			AppendBytes(file, hash);
		}

		private static void RemoveHash(string file)
		{
			using (SHA512 sha512 = SHA512.Create())
			using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
			{
				long fileSize = stream.Length;

				if (fileSize < HASH_SIZE)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.Seek(fileSize - HASH_SIZE, SeekOrigin.Begin);
				byte[] hash = SCommon.Read(stream, HASH_SIZE);
				stream.Seek(0L, SeekOrigin.Begin);
				stream.SetLength(fileSize - HASH_SIZE);
				byte[] recalcHash = sha512.ComputeHash(stream);

				if (SCommon.Comp(hash, recalcHash, SCommon.Comp) != 0)
					throw new Exception("入力データの破損または鍵の不一致を検出しました。");
			}
		}

		private const long REPORT_PERIOD = 16 * 500000;

		private static void EncryptRingCBC(string file, AESCipher transformer, int progressNumer, int progressDenom)
		{
			byte[] input = new byte[16];
			byte[] output = new byte[16];

			using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
			{
				long fileSize = stream.Length;

				if (
					fileSize < 32 ||
					fileSize % 16 != 0
					)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.Seek(fileSize - 16, SeekOrigin.Begin);
				SCommon.Read(stream, output);
				stream.Seek(0L, SeekOrigin.Begin);

				for (long offset = 0; offset < fileSize; offset += 16)
				{
					if (offset % REPORT_PERIOD == 0L)
						ProcMain.WriteLog(
							"ファイルを暗号化しています。" +
							((decimal)progressNumer / progressDenom + ((decimal)offset / fileSize) / progressDenom).ToString("F6") +
							" " +
							((decimal)offset / fileSize).ToString("F3") +
							" " +
							progressNumer +
							"/" +
							progressDenom
							);

					SCommon.Read(stream, input);
					XorBlock(input, output);
					transformer.EncryptBlock(input, output);
					stream.Seek(offset, SeekOrigin.Begin);
					SCommon.Write(stream, output);
				}
			}
		}

		private static void DecryptRingCBC(string file, AESCipher transformer, int progressNumer, int progressDenom)
		{
			byte[] input = new byte[16];
			byte[] output = new byte[16];

			using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.ReadWrite))
			{
				long fileSize = stream.Length;

				if (
					fileSize < 32 ||
					fileSize % 16 != 0
					)
					throw new Exception("Bad fileSize: " + fileSize);

				stream.Seek(fileSize - 16, SeekOrigin.Begin);
				SCommon.Read(stream, input);

				for (long offset = fileSize - 16; 0L <= offset; offset -= 16)
				{
					if (offset % REPORT_PERIOD == 0L)
						ProcMain.WriteLog(
							"ファイルを復号しています。" +
							((decimal)progressNumer / progressDenom + (1m - (decimal)offset / fileSize) / progressDenom).ToString("F6") +
							" " +
							(1m - (decimal)offset / fileSize).ToString("F3") +
							" " +
							progressNumer +
							"/" +
							progressDenom
							);

					transformer.DecryptBlock(input, output);
					stream.Seek((offset + fileSize - 16) % fileSize, SeekOrigin.Begin);
					SCommon.Read(stream, input);
					XorBlock(output, input);

					if (offset == 0L)
						stream.Seek(0L, SeekOrigin.Begin);

					SCommon.Write(stream, output);
				}
			}
		}

		private static void XorBlock(byte[] data, byte[] maskData)
		{
			for (int index = 0; index < 16; index++)
				data[index] ^= maskData[index];
		}

		private static void AppendBytes(string file, byte[] data)
		{
			using (FileStream writer = new FileStream(file, FileMode.Append, FileAccess.Write))
			{
				SCommon.Write(writer, data);
			}
		}
	}
}

//
// <<< Processed by SolutionConv
//