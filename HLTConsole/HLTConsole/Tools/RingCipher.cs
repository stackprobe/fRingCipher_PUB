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
using System.Security.Cryptography;
using HLTStudio.Commons;

namespace HLTStudio.Tools
{
	/// /////////
	/// //////////////////
	/// ///// ///////////// / ///////////////// ////////////////////////
	/// //////////
	public class RingCipher : IDisposable
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
		public RingCipher(byte[] rawKey)
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
		/// ////// /////////////////////////
		/// ////////////////////////
		public byte[] Encrypt(byte[] data)
		{
			if (data == null)
				throw new Exception("Bad data");

			data = AddPadding(data);
			data = AddCRandPart(data, 64);
			data = AddHash(data);
			data = AddCRandPart(data, 16);

			foreach (AESCipher transformer in this.Transformers)
				EncryptRingCBC(data, transformer);

			return data;
		}

		/// /////////
		/// //////
		/// //////////////////////////////
		/// //////////
		/// ////// /////////////////////////
		/// ////////////////////////
		public byte[] Decrypt(byte[] data)
		{
			if (
				data == null ||
				data.Length < 16 + 64 + 64 + 16 || // / /////////////////////// / //////////// / /////// / //////////// ////
				data.Length % 16 != 0
				)
				throw new Exception("入力データの破損を検出しました。");

			data = SCommon.GetPart(data, 0, data.Length); // //

			foreach (AESCipher transformer in this.Transformers.Reverse())
				DecryptRingCBC(data, transformer);

			data = RemoveCRandPart(data, 16);
			data = RemoveHash(data);
			data = RemoveCRandPart(data, 64);
			data = RemovePadding(data);
			return data;
		}

		private static byte[] AddPadding(byte[] data)
		{
			int size = 16 - data.Length % 16;
			byte[] padding = SCommon.CRandom.GetBytes(size);
			size--;
			padding[size] &= 0xf0;
			padding[size] |= (byte)size;
			data = SCommon.Join(new byte[][] { data, padding });
			return data;
		}

		private static byte[] RemovePadding(byte[] data)
		{
			int size = data[data.Length - 1] & 0x0f;
			size++;
			data = SCommon.GetPart(data, 0, data.Length - size);
			return data;
		}

		private static byte[] AddCRandPart(byte[] data, int size)
		{
			byte[] padding = SCommon.CRandom.GetBytes(size);
			data = SCommon.Join(new byte[][] { data, padding });
			return data;
		}

		private static byte[] RemoveCRandPart(byte[] data, int size)
		{
			data = SCommon.GetPart(data, 0, data.Length - size);
			return data;
		}

		private const int HASH_SIZE = 64;

		private static byte[] AddHash(byte[] data)
		{
			byte[] hash = SCommon.GetSHA512(data);

			if (hash.Length != HASH_SIZE)
				throw null; // /////

			data = SCommon.Join(new byte[][] { data, hash });
			return data;
		}

		private static byte[] RemoveHash(byte[] data)
		{
			byte[] hash = SCommon.GetPart(data, data.Length - HASH_SIZE, HASH_SIZE);
			data = SCommon.GetPart(data, 0, data.Length - HASH_SIZE);
			byte[] recalcHash = SCommon.GetSHA512(data);

			if (SCommon.Comp(hash, recalcHash, SCommon.Comp) != 0)
				throw new Exception("入力データの破損または鍵の不一致を検出しました。");

			return data;
		}

		private static void EncryptRingCBC(byte[] data, AESCipher transformer)
		{
			byte[] input = new byte[16];
			byte[] output = new byte[16];

			Array.Copy(data, data.Length - 16, output, 0, 16);

			for (int offset = 0; offset < data.Length; offset += 16)
			{
				Array.Copy(data, offset, input, 0, 16);
				XorBlock(input, output);
				transformer.EncryptBlock(input, output);
				Array.Copy(output, 0, data, offset, 16);
			}
		}

		private static void DecryptRingCBC(byte[] data, AESCipher transformer)
		{
			byte[] input = new byte[16];
			byte[] output = new byte[16];

			Array.Copy(data, data.Length - 16, input, 0, 16);

			for (int offset = data.Length - 16; 0 <= offset; offset -= 16)
			{
				transformer.DecryptBlock(input, output);
				Array.Copy(data, (offset + data.Length - 16) % data.Length, input, 0, 16);
				XorBlock(output, input);
				Array.Copy(output, 0, data, offset, 16);
			}
		}

		private static void XorBlock(byte[] data, byte[] maskData)
		{
			for (int index = 0; index < 16; index++)
				data[index] ^= maskData[index];
		}
	}
}

//
// <<< Processed by SolutionConv
//